import ts from 'typescript';
import path from 'node:path';
import { hash } from '../utils/hash.js';
import { readBounded, sourceFiles } from '../utils/paths.js';
import { CacheStore } from '../cache/store.js';
import { ANALYSIS_VERSION, type FileAnalysis, type Metrics, type Settings, type StaticAnalysis } from '../types/index.js';
import { invariant } from '../utils/errors.js';

export const moduleId = (file: string) => `${file}#<module>`;
export function parseSource(file: string, source: string): FileAnalysis {
  const sourceFile = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, /\.[cm]?tsx$/.test(file) ? ts.ScriptKind.TSX : /\.[cm]?ts$/.test(file) ? ts.ScriptKind.TS : /\.jsx$/.test(file) ? ts.ScriptKind.JSX : ts.ScriptKind.JS);
  const host = ts.createCompilerHost({ noResolve: true, noLib: true, allowJs: true });
  host.getSourceFile = name => name === file ? sourceFile : undefined;
  host.writeFile = () => {};
  const program = ts.createProgram([file], { noResolve: true, noLib: true, allowJs: true }, host);
  const checker = program.getTypeChecker();
  const result: FileAnalysis = { file, hash: hash(source), imports: [], functions: [], calls: [], unsupported: [] };
  const unsupported = new Set<string>();
  const bindings = new Map<ts.Symbol, { target: string; imported?: string }>();
  const functionIds = new Map<ts.Node, string>();
  const modified = new Set<ts.Symbol>();
  const line = (node: ts.Node) => sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
  const isExported = (node: ts.Node) => ts.canHaveModifiers(node) && Boolean(ts.getModifiers(node)?.some(m => m.kind === ts.SyntaxKind.ExportKeyword));
  const isGlobalRequire = (node: ts.Expression) => ts.isIdentifier(node) && node.text === 'require' && !checker.getSymbolAtLocation(node)?.declarations?.some(d => d.getSourceFile() === sourceFile);
  function bind(name: ts.Identifier, target: string, imported?: string) {
    const symbol = checker.getSymbolAtLocation(name); if (symbol) bindings.set(symbol, { target, imported });
  }
  function addImport(source: string, imported: string, local: ts.Identifier, node: ts.Node) {
    result.imports.push({ source, imported, local: local.text, line: line(node) });
    bind(local, `import:${source}`, imported);
  }
  for (const statement of sourceFile.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier)) {
      const source = statement.moduleSpecifier.text; const clause = statement.importClause;
      if (clause?.isTypeOnly) continue;
      if (!clause) result.imports.push({ source, imported: '*', local: '', line: line(statement) });
      if (clause?.name) addImport(source, 'default', clause.name, statement);
      if (clause?.namedBindings) {
        if (ts.isNamespaceImport(clause.namedBindings)) addImport(source, '*', clause.namedBindings.name, statement);
        else for (const element of clause.namedBindings.elements) if (!element.isTypeOnly) addImport(source, element.propertyName?.text ?? element.name.text, element.name, statement);
      }
    }
    if (ts.isExportDeclaration(statement) || ts.isExportAssignment(statement)) unsupported.add('Re-exports and export assignments are not resolved.');
    if (ts.isExpressionStatement(statement) && ts.isCallExpression(statement.expression) && isGlobalRequire(statement.expression.expression) && statement.expression.arguments.length === 1 && ts.isStringLiteral(statement.expression.arguments[0])) {
      result.imports.push({ source: statement.expression.arguments[0].text, imported: '*', local: '', line: line(statement) });
    }
    if (ts.isFunctionDeclaration(statement)) {
      const name = statement.name?.text ?? 'default'; const id = `${file}#${name}:${line(statement)}`;
      result.functions.push({ id, name, line: line(statement), exported: isExported(statement) });
      functionIds.set(statement, id); if (statement.name) bind(statement.name, id);
    }
    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        const init = declaration.initializer;
        if (init && (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) && ts.isIdentifier(declaration.name)) {
          const name = declaration.name.text; const id = `${file}#${name}:${line(declaration)}`;
          result.functions.push({ id, name, line: line(declaration), exported: isExported(statement) });
          functionIds.set(init, id); bind(declaration.name, id);
        }
        if (init && ts.isCallExpression(init) && isGlobalRequire(init.expression) && init.arguments.length === 1 && ts.isStringLiteral(init.arguments[0])) {
          const source = init.arguments[0].text;
          if (ts.isIdentifier(declaration.name)) addImport(source, '*', declaration.name, declaration);
          else if (ts.isObjectBindingPattern(declaration.name)) {
            for (const element of declaration.name.elements) {
              if (ts.isIdentifier(element.name) && (!element.propertyName || ts.isIdentifier(element.propertyName))) addImport(source, element.propertyName?.text ?? element.name.text, element.name, declaration);
              else unsupported.add('Computed require destructuring is unsupported.');
            }
          }
        }
      }
    }
  }
  function writes(node: ts.Node) {
    function changed(target: ts.Node) {
      if (ts.isIdentifier(target)) { const symbol = checker.getSymbolAtLocation(target); if (symbol && bindings.has(symbol)) modified.add(symbol); }
      ts.forEachChild(target, changed);
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment) changed(node.left);
    if (ts.isPostfixUnaryExpression(node) || ts.isPrefixUnaryExpression(node) && [ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(node.operator)) changed(node.operand);
    if (ts.isDeleteExpression(node)) changed(node.expression);
    ts.forEachChild(node, writes);
  }
  writes(sourceFile);
  if (modified.size) unsupported.add('Reassigned functions or mutated imported bindings are not resolved.');
  let visited = 0;
  function visit(node: ts.Node, caller: string) {
    invariant(++visited <= 200000 && result.calls.length <= 20000 && result.functions.length <= 5000 && result.imports.length <= 5000, 'STATIC_ANALYSIS_LIMIT', 'Source AST exceeds analysis complexity limits.');
    let current = caller;
    if (ts.isFunctionLike(node)) {
      const id = functionIds.get(node);
      if (id) current = id;
      else { unsupported.add('Nested functions, callbacks, and methods are not resolved.'); current = `${file}#<unsupported>:${line(node)}`; }
    }
    if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) unsupported.add('Classes and prototype dispatch are unsupported.');
    if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) unsupported.add('Framework JSX invocation is unsupported.');
    if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
      const expression = node.expression;
      if (expression.kind === ts.SyntaxKind.ImportKeyword) unsupported.add('Dynamic imports are unsupported.');
      let base: ts.Expression = expression; const members: string[] = [];
      while (ts.isPropertyAccessExpression(base)) { members.unshift(base.name.text); base = base.expression; }
      if (ts.isElementAccessExpression(base)) unsupported.add('Computed property calls are unsupported.');
      if (ts.isIdentifier(base)) {
        if (['eval', 'Function', 'Proxy', 'Reflect'].includes(base.text)) unsupported.add('Reflection or runtime code generation is unsupported.');
        const symbol = checker.getSymbolAtLocation(base); const binding = symbol && !modified.has(symbol) ? bindings.get(symbol) : undefined;
        if (binding && members.some(member => ['call', 'apply', 'bind'].includes(member))) {
          unsupported.add('Indirect call/apply/bind invocation is unsupported.');
        } else if (binding && !binding.imported && members.length) {
          unsupported.add('Properties of local functions are not resolved.');
        } else if (binding) {
          const member = [...(binding.imported && !['*', 'default'].includes(binding.imported) ? [binding.imported] : []), ...members].join('.') || (binding.imported === '*' ? 'default' : binding.imported);
          result.calls.push({ from: current, target: binding.target, line: line(node), ...(member ? { member } : {}) });
        } else if (base.text === 'require') {
          const topLevelLiteral = ts.isCallExpression(node) && node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0]) && caller === moduleId(file);
          const modeled = topLevelLiteral && result.imports.some(imp => ts.isCallExpression(node) && ts.isStringLiteral(node.arguments[0]) && imp.source === node.arguments[0].text && imp.line === line(node));
          if (!modeled) unsupported.add('Dynamic, inline, conditional, or nested require is unsupported.');
        } else if (!['console', 'JSON', 'Math', 'Number', 'String', 'Boolean', 'Object', 'Array', 'Date', 'RegExp', 'Error'].includes(base.text)) {
          unsupported.add('Unresolved calls or function-value flows may invoke additional code.');
        }
      } else unsupported.add('Calls through expression results or computed targets are unsupported.');
      if (node.arguments?.some(a => ts.isArrowFunction(a) || ts.isFunctionExpression(a) || ts.isIdentifier(a) && Boolean(checker.getSymbolAtLocation(a) && bindings.has(checker.getSymbolAtLocation(a)!)))) unsupported.add('Callback or function-value arguments are unsupported.');
    }
    ts.forEachChild(node, child => visit(child, current));
  }
  visit(sourceFile, moduleId(file));
  if ((sourceFile as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics?.length) unsupported.add('Source has parse errors; call graph is incomplete.');
  result.unsupported = [...unsupported];
  return result;
}

export function resolveLocal(source: string, importer: string, files: Set<string>): string | undefined {
  if (!source.startsWith('.')) return undefined;
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(importer), source));
  const stem = base.replace(/\.[cm]?jsx?$/, '');
  const candidates = [base, ...['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx'].map(ext => base + ext), ...['.ts', '.tsx'].map(ext => stem + ext), ...['index.js', 'index.ts', 'index.mjs', 'index.cjs', 'index.tsx'].map(name => `${base}/${name}`)];
  return candidates.find(f => files.has(f));
}
function manifestEntries(manifest: Record<string, unknown>): string[] {
  const values: string[] = [];
  function collect(value: unknown) {
    if (typeof value === 'string') values.push(value.replace(/^\.\//, ''));
    else if (Array.isArray(value)) value.forEach(collect);
    else if (value && typeof value === 'object') Object.values(value).forEach(collect);
  }
  for (const key of ['main', 'module', 'bin', 'exports']) collect(manifest[key]);
  return [...new Set(values)];
}
export async function analyzeSources(root: string, manifest: Record<string, unknown>, settings: Settings, cache: CacheStore, metrics: Metrics, force = false, signal?: AbortSignal, excludedRoots: string[] = []): Promise<StaticAnalysis> {
  const files: FileAnalysis[] = [];
  let timedOut = false;
  for (const full of await sourceFiles(root, settings, metrics, signal, excludedRoots)) {
    if (signal?.aborted) { timedOut = true; break; }
    const source = (await readBounded(root, full, Math.min(settings.maxFileBytes, 2 * 1024 * 1024))).toString('utf8'); metrics.files_examined++;
    const file = path.relative(root, full).replaceAll('\\', '/'); const contentHash = hash(source);
    const key = `${ANALYSIS_VERSION}:${file}:${contentHash}`;
    const cached = force ? undefined : await cache.get<FileAnalysis>('static', key, metrics);
    if (cached) { files.push(cached); metrics.static_files_reused++; }
    else {
      const parsed = parseSource(file, source); files.push(parsed); metrics.static_files_analyzed++;
      await cache.set('static', key, parsed, 7 * 86400000);
    }
  }
  invariant(files.reduce((sum, f) => sum + f.calls.length + f.functions.length + f.imports.length, 0) <= 200000, 'STATIC_ANALYSIS_LIMIT', 'Project call graph exceeds analysis complexity limits.');
  const available = new Set(files.map(f => f.file)); const requested = manifestEntries(manifest);
  const entries = requested.filter(f => available.has(f)); const warnings: string[] = [];
  if (timedOut || metrics.discovery_incomplete) warnings.push('SCAN_TIMEOUT: Static analysis or file discovery stopped at the report time budget; remaining files were not analyzed.');
  if (requested.some(f => !available.has(f))) warnings.push('Some declared entry points are absent or unsupported (including ignored build output).');
  if (!entries.length) {
    for (const candidate of ['index.js', 'index.ts', 'src/index.js', 'src/index.ts', 'app.js', 'server.js']) if (available.has(candidate)) entries.push(candidate);
    warnings.push('Application entry points are inferred or unavailable; external invocation cannot be excluded.');
  }
  for (const f of files) {
    for (const item of f.unsupported) warnings.push(`${f.file}: ${item}`);
    for (const imp of f.imports) if (imp.source.startsWith('.') && !resolveLocal(imp.source, f.file, available)) warnings.push(`${f.file}: Local module could not be resolved.`);
    for (const call of f.calls) if (call.target.startsWith('import:.')) {
      const target = resolveLocal(call.target.slice(7), f.file, available);
      if (!files.find(file => file.file === target)?.functions.some(fn => fn.exported && fn.name === call.member)) warnings.push(`${f.file}: Imported function could not be resolved.`);
    }
  }
  if (files.some(f => f.functions.some(fn => fn.exported))) warnings.push('Exported functions may be called externally; a closed application model is not established.');
  return { files, entries, warnings: [...new Set(warnings)], complete: warnings.length === 0 && entries.length > 0 };
}
