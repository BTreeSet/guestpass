import { useCallback, useEffect, useState } from "react";

import { fire, loadView, passPath, type FireState, type LoadState, type Reading, type Verb, type View } from "./api";
import { Action, DeviceLink, Notice, ReadingLine } from "./view";

const never = (value: never): never => {
  throw new TypeError(`unhandled variant: ${JSON.stringify(value)}`);
};

/** Load state and request state are independent axes: a stale reading can sit
 *  under an in-flight request, and a refusal does not erase the last reading.
 *  Keeping them apart is why neither has to carry the other's fields. */
export default function App() {
  const [load, setLoad] = useState<LoadState>({ status: "loading" });
  const [request, setRequest] = useState<FireState>({ status: "idle" });

  useEffect(() => {
    const controller = new AbortController();
    loadView(controller.signal).then(
      (view) => setLoad({ status: "ready", view }),
      (error: unknown) => {
        if (!controller.signal.aborted) {
          setLoad({ status: "error", message: describe(error) });
        }
      },
    );
    return () => controller.abort();
  }, []);

  const onFire = useCallback((verb: Verb, target: string) => {
    const controller = new AbortController();
    setRequest({ status: "sending", verb });
    fire(target, controller.signal).then(
      (reading) => {
        setRequest({ status: "idle" });
        setLoad((current) => applyReading(current, reading));
      },
      (error: unknown) => {
        if (!controller.signal.aborted) {
          setRequest({ status: "failed", message: describe(error) });
        }
      },
    );
  }, []);

  switch (load.status) {
    case "loading":
      // 100-400ms shows nothing but the result, so this frame stays bare.
      return <main className="page" aria-busy="true" />;
    case "error":
      return (
        <main className="page">
          <Notice title="This pass did not open" body={load.message} />
        </main>
      );
    case "ready":
      return <Ready view={load.view} request={request} onFire={onFire} />;
    default:
      return never(load);
  }
}

function Ready({
  view,
  request,
  onFire,
}: {
  readonly view: View;
  readonly request: FireState;
  readonly onFire: (verb: Verb, target: string) => void;
}) {
  const base = passPath();

  switch (view.at) {
    case "devices":
      return (
        <main className="page">
          <p className="page__label">{view.label}</p>
          <h1 className="page__title">Pick a device</h1>
          <ul className="devices">
            {view.devices.map((device) => (
              <DeviceLink key={device.id} device={device} href={`${base}/${device.id}`} />
            ))}
          </ul>
        </main>
      );

    case "verbs":
      return (
        <main className="page">
          <p className="page__label">{view.label}</p>
          <h1 className="page__title">{view.device.label}</h1>
          <ReadingLine reading={view.device.reading} />
          <div className="actions actions--pair">
            <Action verb="on" label="On" fireState={request} onFire={(v) => onFire(v, `${base}/on`)} />
            <Action verb="off" label="Off" fireState={request} onFire={(v) => onFire(v, `${base}/off`)} />
          </div>
          {request.status === "failed" ? <Notice title="That did not go through" body={request.message} /> : null}
        </main>
      );

    case "call":
      return (
        <main className="page">
          <p className="page__label">{view.label}</p>
          <h1 className="page__title">{view.device.label}</h1>
          <ReadingLine reading={view.device.reading} />
          <div className="actions">
            <Action
              verb={view.verb}
              label={view.verb === "on" ? `Turn on ${view.device.label}` : `Turn off ${view.device.label}`}
              fireState={request}
              onFire={(v) => onFire(v, base)}
            />
          </div>
          {request.status === "failed" ? <Notice title="That did not go through" body={request.message} /> : null}
        </main>
      );

    default:
      return never(view);
  }
}

/** The server's post-fire reading is authoritative, so it replaces whatever the
 *  page was showing rather than being predicted locally. */
function applyReading(current: LoadState, reading: Reading): LoadState {
  if (current.status !== "ready") return current;
  const { view } = current;
  switch (view.at) {
    case "devices":
      return current;
    case "verbs":
      return { status: "ready", view: { ...view, device: { ...view.device, reading } } };
    case "call":
      return { status: "ready", view: { ...view, device: { ...view.device, reading } } };
    default:
      return never(view);
  }
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : "Something went wrong. Try again.";
}
