// A current server-side grant selects one bounded role. Client labels never
// supply scopes; ownership is the separately configured verified mailbox.
export const STAFF_ROLES=Object.freeze(['captain','coordinator','editor','publisher','module-verifier','module-approver','safety-reviewer','treasurer','security-administrator','auditor']);
const scopes={
 captain:['team:manage','task:review'],
 coordinator:['team:manage','task:manage','task:review','tools:manage','training:manage','operations:read'],
 editor:['content:edit','activity:edit'],
 publisher:['content:publish','activity:publish'],
 'module-verifier':['activity:verify'],
 'module-approver':['activity:publish'],
 'safety-reviewer':['safety:review'],
 treasurer:['finance:read','finance:manage'],
 'security-administrator':['security:read','security:manage','operations:read'],
 auditor:['operations:read','finance:metadata']
};
export function staffScopes(role){return role==='owner'?['*']:scopes[role]?[...scopes[role]]:[];}
export function staffCan(role,scope){return staffScopes(role).some(s=>s==='*'||s===scope);}
