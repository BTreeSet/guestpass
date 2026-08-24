/** Wire types. These mirror the Rust enums; a new variant on either side
 *  fails the exhaustive switch in `view.tsx` rather than rendering blank. */

export type Verb = "on" | "off";

/** What the server last knew about a device. `state` separates our link to
 *  Home Assistant from the device's own availability, which vary apart. */
export type Reading =
  | { readonly state: "unknown" }
  | { readonly state: "offline" }
  | { readonly state: "live"; readonly on: boolean }
  | { readonly state: "stale"; readonly on: boolean };

export interface DeviceView {
  readonly id: string;
  readonly label: string;
  readonly reading: Reading;
}

/** The position the URL names. One variant per arity of the request fold. */
export type View =
  | { readonly at: "devices"; readonly label: string; readonly devices: readonly DeviceView[] }
  | { readonly at: "verbs"; readonly label: string; readonly device: DeviceView }
  | { readonly at: "call"; readonly label: string; readonly device: DeviceView; readonly verb: Verb };

export type LoadState =
  | { readonly status: "loading" }
  | { readonly status: "error"; readonly message: string }
  | { readonly status: "ready"; readonly view: View };

export type FireState =
  | { readonly status: "idle" }
  | { readonly status: "sending"; readonly verb: Verb }
  | { readonly status: "failed"; readonly message: string };

/** The pass path this page was served from. The token is the credential and
 *  it is already in the URL, so nothing else is stored or sent. */
export const passPath = (): string => window.location.pathname.replace(/\/+$/, "");

const asJson = { Accept: "application/json" };

export async function loadView(signal: AbortSignal): Promise<View> {
  const response = await fetch(passPath(), { headers: asJson, signal });
  if (!response.ok) throw new Error(await message(response));
  return (await response.json()) as View;
}

export async function fire(path: string, signal: AbortSignal): Promise<Reading> {
  const response = await fetch(path, {
    method: "POST",
    headers: asJson,
    signal,
  });
  if (!response.ok) throw new Error(await message(response));
  return (await response.json()) as Reading;
}

async function message(response: Response): Promise<string> {
  const text = (await response.text()).trim();
  return text.length > 0 ? text : `Request failed (${response.status}).`;
}
