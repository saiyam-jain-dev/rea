import { expect, it } from "vitest";

import { createEvidence } from "../evidence.js";
import type { PythonPyc } from "../python/pythonPyc.js";
import {
  projectAnalysisView,
  type AnalysisViewParent,
  type AnalysisViewRequest,
} from "./analysisView.js";

const report: PythonPyc = {
  artifact: {
    path: "/artifacts/module.pyc",
    sha256: "a".repeat(64),
    bytes: 48,
  },
  header: {
    magic: 3413,
    python_version: "3.8",
    code_layout: "py38",
    flags: 0,
    hash_based: false,
    check_source: false,
    source_hash_hex: null,
    source_mtime: 1600000000,
    source_size: 100,
  },
  code_objects: [
    {
      name: "<module>",
      qualname: null,
      filename: "module.py",
      firstlineno: 1,
      argcount: 0,
      posonlyargcount: 0,
      kwonlyargcount: 0,
      nlocals: 0,
      stacksize: 1,
      flags: 64,
      names: ["func"],
      varnames: null,
      freevars: null,
      cellvars: null,
      localsplusnames: null,
      localspluskinds_hex: null,
      bytecode: { bytes: 4, sha256: "b".repeat(64) },
      consts: [{ kind: "none" }],
      nested_code: [1],
    },
    {
      name: "func",
      qualname: "func",
      filename: "module.py",
      firstlineno: 2,
      argcount: 1,
      posonlyargcount: 0,
      kwonlyargcount: 0,
      nlocals: 1,
      stacksize: 2,
      flags: 67,
      names: [],
      varnames: ["x"],
      freevars: null,
      cellvars: null,
      localsplusnames: null,
      localspluskinds_hex: null,
      bytecode: { bytes: 8, sha256: "c".repeat(64) },
      consts: [],
      nested_code: [],
    },
  ],
  coverage: {
    status: "complete",
    objects: 2,
    code_objects: 2,
    marshal_bytes: 32,
    marshal_depth: 2,
  },
  limitations: ["Bytecode is not decompiled."],
};

const parent = (value = structuredClone(report)): AnalysisViewParent => {
  const evidence = createEvidence(
    {
      path: value.artifact.path,
      sha256: value.artifact.sha256,
      format: "file",
    },
    {
      id: "python-pyc",
      name: "REA Python pyc reader",
      version: "1",
    },
    {
      operation: "inspect_python_pyc",
      parameters: { path: value.artifact.path },
      result: value,
    },
  );
  return {
    evidenceId: evidence.evidence_id,
    operation: evidence.operation,
    subject: evidence.subject,
    normalizedResult: value,
    limitations: [],
  };
};

it("projects a summary view with limitation count and complete within-view coverage", () => {
  const source = parent();
  const result = projectAnalysisView(source, { kind: "summary" });
  if (!result.ok) throw result.error;
  expect(result.value).toMatchObject({
    kind: "summary",
    parent_operation: "inspect_python_pyc",
    summary: {
      artifact: {
        path: "/artifacts/module.pyc",
        bytes: 48,
      },
      header: {
        python_version: "3.8",
        magic: 3413,
      },
      limitation_count: 1,
    },
    coverage: {
      status: "complete-within-view",
      examined: 2,
      total: 2,
    },
  });
});

it("pages code objects with default fields and attaches source_index", () => {
  const source = parent();
  const result = projectAnalysisView(source, {
    kind: "python-pyc",
    collection: "code_objects",
    offset: 0,
    limit: 10,
  });
  if (!result.ok || result.value.kind !== "python-pyc")
    throw new Error("Python pyc code objects page failed");
  expect(result.value.items).toEqual([
    {
      ...report.code_objects[0],
      source_index: 0,
    },
    {
      ...report.code_objects[1],
      source_index: 1,
    },
  ]);
  expect(result.value.coverage).toMatchObject({
    total: 2,
    examined: 2,
    exhausted: true,
    next_offset: null,
  });
});

it("filters code objects by name", () => {
  const source = parent();
  const result = projectAnalysisView(source, {
    kind: "python-pyc",
    collection: "code_objects",
    names: ["func"],
    offset: 0,
    limit: 10,
  });
  if (!result.ok || result.value.kind !== "python-pyc")
    throw new Error("Python pyc filter by name failed");
  expect(result.value.items).toEqual([
    {
      ...report.code_objects[1],
      source_index: 1,
    },
  ]);
  expect(result.value.coverage.total).toBe(1);
});

it("filters code objects by index", () => {
  const source = parent();
  const result = projectAnalysisView(source, {
    kind: "python-pyc",
    collection: "code_objects",
    indices: [0],
    offset: 0,
    limit: 10,
  });
  if (!result.ok || result.value.kind !== "python-pyc")
    throw new Error("Python pyc filter by index failed");
  expect(result.value.items).toEqual([
    {
      ...report.code_objects[0],
      source_index: 0,
    },
  ]);
  expect(result.value.coverage.total).toBe(1);
});

it("projects sparse field subsets while retaining source_index", () => {
  const source = parent();
  const result = projectAnalysisView(source, {
    kind: "python-pyc",
    collection: "code_objects",
    fields: ["name", "firstlineno"],
    offset: 0,
    limit: 1,
  });
  if (!result.ok || result.value.kind !== "python-pyc")
    throw new Error("Python pyc sparse fields failed");
  expect(result.value.items).toEqual([
    {
      name: "<module>",
      firstlineno: 1,
      source_index: 0,
    },
  ]);
  expect(result.value.coverage).toMatchObject({
    total: 2,
    examined: 1,
    exhausted: false,
    next_offset: 1,
  });
});

it("rejects unsupported view kinds with an input error", () => {
  const source = parent();
  const invalid = projectAnalysisView(source, {
    kind: "cve",
  } as unknown as AnalysisViewRequest);
  expect(invalid.ok).toBe(false);
  if (!invalid.ok) {
    expect(invalid.error).toMatchObject({
      operation: "inspect_analysis_view",
      issues: [
        {
          path: ["view"],
          reason: "invalid_value",
          message: "Python pyc Evidence supports summary and python-pyc views.",
        },
      ],
    });
  }
});
