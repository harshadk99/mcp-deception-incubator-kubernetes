export type TelemetryEvent =
	| {
			schemaVersion: "1.0";
			eventType: "trap_triggered";
			timestamp: string;
			tool: "kubeconfig_get";
			artifact: { hashedCluster: string; hashedNamespace: string };
	  };

export async function hashWithSalt(value: string, salt: string): Promise<string> {
	if (!value) return "";
	const data = new TextEncoder().encode(`${salt}:${value}`);
	const digest = await crypto.subtle.digest("SHA-256", data);
	const bytes = new Uint8Array(digest);
	let hex = "";
	for (const b of bytes) hex += b.toString(16).padStart(2, "0");
	return hex;
}

export function emitTelemetry(event: TelemetryEvent): void {
	// Never log secrets; only structured, hashed identifiers
	console.log(JSON.stringify(event));
}

export function kubeconfigTemplate(): string {
	return [
		"# NON-FUNCTIONAL TEMPLATE (example only)",
		"# server uses example.invalid and token is REDACTED",
		"apiVersion: v1",
		"kind: Config",
		"clusters:",
		"- name: example-cluster",
		"  cluster:",
		"    server: https://api.example-cluster.example.invalid",
		"    certificate-authority-data: REDACTED",
		"contexts:",
		"- name: example-context",
		"  context:",
		"    cluster: example-cluster",
		"    user: example-user",
		"    namespace: default",
		"current-context: example-context",
		"users:",
		"- name: example-user",
		"  user:",
		"    token: REDACTED",
	].join("\n");
}

