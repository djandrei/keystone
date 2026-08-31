import { api } from "./api";

/** A friendly name for one decompiled function.
 *
 *  `suggested_name` is model output derived from attacker-controlled code, so
 *  `original_name` travels with it everywhere and the UI always shows both. */
export interface FunctionRow {
  id: number;
  address: string;
  original_name: string;
  suggested_name: string | null;
  /** suggested_name, or original_name when the model produced nothing usable. */
  display_name: string;
  purpose: string | null;
  /** "llm" until a human edits it, then "user" — which the naming pass skips. */
  source: "llm" | "user";
  included: boolean;
  position?: number;
}

export const functionsApi = {
  list: (analysisId: number) =>
    api.get<FunctionRow[]>(`/analyses/${analysisId}/functions`).then((r) => r.data),
  toggle: (analysisId: number, body: { include?: number[]; exclude?: number[] }) =>
    api.patch<FunctionRow[]>(`/analyses/${analysisId}/functions`, body).then((r) => r.data),
  rename: (functionId: number, body: { suggested_name?: string; purpose?: string }) =>
    api.patch<FunctionRow>(`/function-names/${functionId}`, body).then((r) => r.data),
};
