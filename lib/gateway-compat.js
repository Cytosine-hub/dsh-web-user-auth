// Explicit build/install-time compatibility repair; never runs during plugin activation.
import { createHash } from 'node:crypto'
const RAW='4fbe460fec585ebc2cf2887261f6c33f024081a539d9fb5d6557a9002324b23f'
const APPROVAL='96143ba1eafe5154964c8578af1dd1c172c786aa33fe401ccdebb6d6df8861a2'
const digest=source=>createHash('sha256').update(source).digest('hex')
function transform(source){
function replace(before, after) {
  if (source.split(before).length !== 2) throw new Error('Gateway compatibility anchor must occur exactly once')
  source = source.replace(before, after)
}
replace('if (peer.principal.kind !== "owner") throw new TypertGatewayError("gateway/invocation-unavailable", endpoint, "only owner Peers answer forwarded Remote events");',
  'if (!["owner", "harness-user", "harness-admin"].includes(peer.principal.kind)) throw new TypertGatewayError("gateway/interactions-forbidden", endpoint, "Peer cannot answer Remote events");')
replace('answers: peer.principal.kind === "owner"', 'answers: ["owner", "harness-user", "harness-admin"].includes(peer.principal.kind)')
// answers is transport capability, never authorization to receive all notifications.
replace('if (!client.answers) {', 'if (client.principal.kind !== "owner") {')
replace('\tdeliverRemoteEvent(pending, client) {', `	canAnswerSessionInteraction(pending, client) {
		if (client.signal.aborted || client.peer.signal.aborted) return false;
		if (client.principal.kind === "owner") return true;
		if (!["harness-user", "harness-admin"].includes(client.principal.kind)) return false;
		if (!["approval/request", "user-questions/request"].includes(pending.source.event)) return false;
		// The subject is the server's scoped Agent, never a browser/model argument.
		const sessionId = pending.source.context.subject?.session?.id;
		if (typeof sessionId !== "string" || !sessionId) return false;
		try {
			return this.ctx.remoteAccess.decide({
				principal: client.principal,
				action: "session/control",
				resources: [{ kind: "session", id: sessionId }],
				args: { sessionId }
			}).kind === "allow";
		} catch { return false; }
	}
	deliverRemoteEvent(pending, client) {
		if (!this.canAnswerSessionInteraction(pending, client)) return;`)
replace('if (pending === void 0 || !pending.deliveries.has(client)) return;', `if (pending === void 0 || !pending.deliveries.has(client)) return;
		if (!this.canAnswerSessionInteraction(pending, client)) throw new TypertGatewayError("gateway/interactions-forbidden", "$events/result", "Session interaction access was revoked");`)
return source
}
export function repairGateway(source,manifest){
  if(manifest.name!=='@deepseek-ai/dsh-api-gateway'||manifest.version!=='0.2.1-rc.2')throw new Error('Unsupported Gateway package/version; review upstream before applying')
  const hash=digest(source)
  if(hash===RAW)return {status:'repair-required',source:transform(source)}
  if(hash===APPROVAL){
    const updated=source.replaceAll('canAnswerSessionApproval','canAnswerSessionInteraction').replace('if (pending.source.event !== "approval/request") return false;', 'if (!["approval/request", "user-questions/request"].includes(pending.source.event)) return false;').replace('Session approval access was revoked','Session interaction access was revoked')
    return {status:'repair-required',source:updated}
  }
  if(hash===FIXED)return {status:'compatible',source}
  throw new Error('Gateway bytes are not a reviewed release; no changes made')
}
const FIXED='6cf98798e6e67ff179e971a851ad35cf5029d265ff01ad6edac12b34a2dfe804'
