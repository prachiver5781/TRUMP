import { randomUUID } from 'node:crypto';
import { VERSION, type DependencyGraph } from '../types/index.js';

export function generateSbom(graph: DependencyGraph) {
  return {
    bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: `urn:uuid:${randomUUID()}`, version: 1,
    metadata: { timestamp: new Date().toISOString(), tools: [{ vendor: 'TRACEGUARD', name: 'traceguard-mcp', version: VERSION }],
      component: { type: 'application', 'bom-ref': 'root', name: graph.name, version: graph.version } },
    components: graph.nodes.map(node => ({ type: 'library', 'bom-ref': node.id, name: node.name, version: node.version,
      purl: `pkg:npm/${node.name.startsWith('@') ? `${encodeURIComponent(node.name.split('/')[0])}/${encodeURIComponent(node.name.split('/')[1])}` : encodeURIComponent(node.name)}@${encodeURIComponent(node.version)}`,
      scope: 'required', properties: [{ name: 'traceguard:dev', value: String(node.dev) }, { name: 'traceguard:optional', value: String(node.optional) }, { name: 'traceguard:location', value: node.location }] })),
    dependencies: [{ ref: 'root', dependsOn: graph.root_children }, ...graph.nodes.map(node => ({ ref: node.id, dependsOn: node.children }))]
  };
}
