import { dirname, join } from "node:path";
import type { ZodType } from "zod/v4";
import commonSchema from "../../schemas/definitions/artifact-common.schema.json";
import reducerSchema from "../../schemas/tools/deep-reducer.schema.json";
import scanDraftSchema from "../../schemas/tools/scan-draft.schema.json";
import type { ArtifactContext } from "./artifact-context.js";
import {
  artifactDestination,
  readArtifactText,
  replaceArtifactText,
} from "./artifact-io.js";
import type { DeepReducerPageInput } from "./artifact-deep-reducer-pages.js";
import {
  parsePersistedScanDraft,
  saveScanDraftCheckpoint,
} from "./artifact-scan-draft.js";
import {
  loadArtifactZodSchema,
  type SchemaDocument,
} from "./artifact-schema-loader.js";
import { saveThreatModelDocument } from "./threat-model-document.js";
import {
  createDeepScanArtifacts,
  readJsonObject,
  requireRegularFile,
  writeJsonAtomic,
} from "./deep-scan/artifacts.js";
import {
  parseDeepReduction,
  parseStoredScanDraft,
  reconcileDeepReduction,
  type DeepReductionInput,
  type DeepReductionSources,
} from "./deep-scan/artifact-validation.js";

const schemaDocuments = [
  commonSchema,
  scanDraftSchema,
  reducerSchema,
] as SchemaDocument[];

export const deepReducerInputsInputSchema = loadArtifactZodSchema(
  schemaDocuments,
  reducerSchema.$id,
  "reducerInputs",
) as ZodType<DeepReducerPageInput>;

export const deepReductionInputSchema = loadArtifactZodSchema(
  schemaDocuments,
  reducerSchema.$id,
  "reductionInput",
) as ZodType<DeepReductionInput>;

/** Read the findings and scan context assigned to this reducer. */
export async function getCodexSecurityDeepReducerInputs(
  context: ArtifactContext,
): Promise<DeepReductionSources> {
  return withLogicalReducerErrors(context, async () => {
    const bound = bindDeepReducer(context);
    const discoveries = await Promise.all(
      bound.state.claimedWorkers.map(async (worker) => {
        await requireRegularFile(
          worker.resultPath,
          bound.artifacts.workersRoot,
        );
        const result = parseStoredScanDraft(
          await readJsonObject(worker.resultPath),
          "Accepted Standard worker " + worker.id,
          bound.scanId,
          parsePersistedScanDraft,
          " has an invalid Standard scan result: ",
          " belongs to a different scan.",
        );
        if (result.complete === false)
          throw new Error(
            "An assigned Standard worker wrote only a checkpoint, not a complete result.",
          );
        for (const [index, finding] of result.findings.entries()) {
          const provenance = finding.provenance as Record<string, unknown>;
          provenance.sourceFindingIds = [`${worker.id}:${index}`];
        }
        const { coverage: _coverage, ...reduction } = result;
        return { workerId: worker.id, result: reduction };
      }),
    );
    const previous = await readPreviousReduction(bound);
    const scanId =
      bound.scanId ?? previous?.scanId ?? discoveries[0]?.result.scanId;
    for (const discovery of discoveries) {
      if (discovery.result.scanId !== scanId) {
        throw new Error(
          "Accepted Standard worker " +
            discovery.workerId +
            " belongs to a different scan.",
        );
      }
    }
    return { discoveries, previous };
  });
}

/** Check and save the reducer's finished result. */
export async function recordCodexSecurityDeepReduction(
  context: ArtifactContext,
  input: unknown,
): Promise<{
  findingCount: number;
  consumedWorkerIds: string[];
  warnings?: string[];
}> {
  return withLogicalReducerErrors(context, async () => {
    const bound = bindDeepReducer(context);
    const submitted = deepReductionInputSchema.parse(input);
    let reduction = parseDeepReduction(submitted);
    if (reduction.complete === false)
      throw new Error(
        "Deep reduction is only a checkpoint, not a complete result.",
      );
    const inputs = await getCodexSecurityDeepReducerInputs(context);
    const expectedScanId =
      bound.scanId ??
      inputs.previous?.scanId ??
      inputs.discoveries[0]?.result.scanId;
    if (reduction.scanId !== expectedScanId) {
      throw new Error(
        "Deep reduction scanId does not match its assigned Standard results.",
      );
    }
    reduction = reconcileDeepReduction(
      reduction,
      inputs.discoveries,
      inputs.previous,
    );

    const writeupWarnings = await materializeDeepWriteups(
      context,
      reduction,
      inputs,
    );

    await saveScanDraftCheckpoint(context, reduction);
    await writeJsonAtomic(bound.resultPath, reduction);
    const documentWarning = await saveThreatModelDocument(
      context,
      reduction.threatModel,
    );
    return {
      findingCount: reduction.findings.length,
      consumedWorkerIds: bound.state.claimedWorkers.map((worker) => worker.id),
      ...(documentWarning === undefined && writeupWarnings.length === 0
        ? {}
        : {
            warnings: [
              ...writeupWarnings,
              ...(documentWarning === undefined ? [] : [documentWarning]),
            ],
          }),
    };
  });
}

async function materializeDeepWriteups(
  context: ArtifactContext,
  reduction: DeepReductionInput,
  inputs: DeepReductionSources,
): Promise<string[]> {
  const deepReducer = context.deepReducer!;
  const scanContext: ArtifactContext = {
    root: deepReducer.scanRoot,
    repoRoot: context.repoRoot,
    layout: "scan",
  };
  const workerRoots = new Map(
    inputs.discoveries.map(({ workerId }) => [
      workerId,
      dirname(
        deepReducer.claimedWorkers.find((worker) => worker.id === workerId)!
          .resultPath,
      ),
    ]),
  );
  const warnings: string[] = [];

  for (const [index, finding] of reduction.findings.entries()) {
    const writeup = finding.writeup;
    if (
      writeup === undefined ||
      writeup === null ||
      typeof writeup !== "object"
    )
      continue;
    const reportPath = (writeup as Record<string, unknown>).reportPath;
    if (typeof reportPath !== "string") continue;
    const components = reportPath.split("/");
    const provenance = finding.provenance as Record<string, unknown>;
    const sourceIds = Array.isArray(provenance.sourceFindingIds)
      ? provenance.sourceFindingIds.filter(
          (id): id is string => typeof id === "string",
        )
      : [];
    const sourceWorkerRoots = sourceIds.flatMap((id) => {
      const workerId = [...workerRoots.keys()].find((candidate) =>
        id.startsWith(`${candidate}:`),
      );
      return workerId === undefined ? [] : [workerRoots.get(workerId)!];
    });
    const roots = [
      context.root,
      ...(deepReducer.previousReducerResultPath
        ? [dirname(deepReducer.previousReducerResultPath)]
        : []),
      ...sourceWorkerRoots,
    ];
    let contents: string | undefined;
    for (const root of new Set(roots)) {
      try {
        contents = await readArtifactText(
          { root, repoRoot: context.repoRoot, layout: "reducer" },
          components,
          `Deep finding write-up ${index + 1}`,
        );
        break;
      } catch {
        // A write-up can live in a source worker rather than the reducer output.
      }
    }
    if (contents === undefined) {
      delete finding.writeup;
      warnings.push(
        `Removed unavailable write-up reference from Deep finding ${index + 1}.`,
      );
      continue;
    }
    try {
      const existing = await readArtifactText(
        scanContext,
        components,
        `Deep finding write-up ${index + 1}`,
      );
      if (existing !== contents) {
        throw new Error(
          `Deep finding write-up path conflicts with existing scan content: ${reportPath}`,
        );
      }
      continue;
    } catch (error) {
      if (
        error instanceof Error &&
        !error.message.endsWith("the requested artifact is unavailable.")
      ) {
        throw error;
      }
    }
    const destination = await artifactDestination(
      scanContext,
      components,
      `Deep finding write-up ${index + 1}`,
    );
    await replaceArtifactText(destination, contents);
  }
  return warnings;
}

function bindDeepReducer(context: ArtifactContext) {
  const state = context.deepReducer;
  if (context.layout !== "reducer" || !state) {
    throw new Error(
      "No active Deep reducer is bound to this scan; " +
        "start an assigned Deep reduction before using reducer operations.",
    );
  }
  if (state.claimedWorkers.length === 0) {
    throw new Error(
      "The active Deep reducer has no assigned Standard scan workers.",
    );
  }
  const workerIds = new Set<string>();
  for (const worker of state.claimedWorkers) {
    if (!worker.id.trim()) {
      throw new Error(
        "An assigned Standard scan worker has no worker identity.",
      );
    }
    if (workerIds.has(worker.id)) {
      throw new Error(
        "The active Deep reducer repeats assigned Standard scan worker " +
          worker.id +
          ".",
      );
    }
    workerIds.add(worker.id);
  }

  return {
    artifacts: createDeepScanArtifacts(state.scanRoot),
    state,
    resultPath: join(context.root, "result.json"),
    ...(context.scanId === undefined ? {} : { scanId: context.scanId }),
  };
}

async function readPreviousReduction(
  bound: ReturnType<typeof bindDeepReducer>,
): Promise<DeepReductionInput | null> {
  const { previousReducerResultPath } = bound.state;
  if (!previousReducerResultPath) return null;
  await requireRegularFile(
    previousReducerResultPath,
    bound.artifacts.dedupRoot,
  );
  return parseStoredScanDraft(
    await readJsonObject(previousReducerResultPath),
    "The previous accepted Deep reduction",
    bound.scanId,
    (value) => parseDeepReduction(value, true),
    " has an invalid Standard scan result: ",
    " belongs to a different scan.",
  );
}

async function withLogicalReducerErrors<Result>(
  context: ArtifactContext,
  run: () => Promise<Result>,
): Promise<Result> {
  try {
    return await run();
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    let message = error.message;
    const roots = [context.deepReducer?.scanRoot, context.root]
      .filter((value): value is string => Boolean(value))
      .sort((left, right) => right.length - left.length);
    for (const root of roots) {
      message = message.replaceAll(root, "<scan artifacts>");
    }
    message = message.replace(
      /<scan artifacts>\/[\w./-]*/gu,
      "<scan artifact>",
    );
    if (message === error.message) throw error;
    const publicError = new Error(message, { cause: error });
    for (const key of ["code", "jsonPointer", "expected"] as const) {
      if (key in error) {
        Object.defineProperty(publicError, key, {
          configurable: true,
          enumerable: true,
          value: Reflect.get(error, key),
          writable: true,
        });
      }
    }
    throw publicError;
  }
}
