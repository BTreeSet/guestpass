import type { DeviceView, FireState, Reading, Verb } from "./api";

const never = (value: never): never => {
  throw new TypeError(`unhandled variant: ${JSON.stringify(value)}`);
};

/** Device state, told honestly. `unknown` and `offline` are distinct: one is
 *  our link to Home Assistant, the other is the device itself. */
export function ReadingLine({ reading }: { readonly reading: Reading }) {
  switch (reading.state) {
    case "unknown":
      return <Line kind="unknown" text="State not known yet" />;
    case "offline":
      return <Line kind="unknown" text="Device is unavailable" />;
    case "live":
      return <Line kind={reading.on ? "on" : "off"} text={reading.on ? "On" : "Off"} />;
    case "stale":
      return <Line kind={reading.on ? "on" : "off"} text={reading.on ? "On, last known" : "Off, last known"} />;
    default:
      return never(reading);
  }
}

function Line({ kind, text }: { readonly kind: "on" | "off" | "unknown"; readonly text: string }) {
  return (
    <span className="reading">
      {/* The dot repeats the word rather than replacing it, so no state is
          carried by colour alone. */}
      <span className={`reading__dot reading__dot--${kind}`} aria-hidden="true" />
      {text}
    </span>
  );
}

export function DeviceLink({ device, href }: { readonly device: DeviceView; readonly href: string }) {
  return (
    <li>
      <a className="device" href={href}>
        <span className="device__name">{device.label}</span>
        <ReadingLine reading={device.reading} />
      </a>
    </li>
  );
}

export function Action({
  verb,
  label,
  fireState,
  onFire,
}: {
  readonly verb: Verb;
  readonly label: string;
  readonly fireState: FireState;
  readonly onFire: (verb: Verb) => void;
}) {
  const sending = fireState.status === "sending" && fireState.verb === verb;
  return (
    <button
      type="button"
      className={`action ${verb === "on" ? "action--primary" : ""}`}
      onClick={() => onFire(verb)}
      disabled={fireState.status === "sending"}
      aria-busy={sending}
    >
      {label}
      {/* The label is preserved so the control never resizes mid-press. */}
      {sending ? <span className="action__state">Sending</span> : null}
    </button>
  );
}

export function Notice({ title, body }: { readonly title: string; readonly body: string }) {
  return (
    <div className="notice" role="status">
      <p className="notice__title">{title}</p>
      <p className="notice__body">{body}</p>
    </div>
  );
}
