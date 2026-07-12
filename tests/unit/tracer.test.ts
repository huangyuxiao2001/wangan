/**
 * 溯源分析模块 — 单元测试
 */
import { Tracer, ToolCallRecord, CallGraph } from '../../src/tracer/call-graph';
import { DagRenderer } from '../../src/tracer/dag-renderer';
import { AuditLogger } from '../../src/tracer/audit-logger';
import * as fs from 'fs';

const LOG_PATH = './logs/test-audit-logger.jsonl';

// ===== CallGraph =====
describe('Tracer — CallGraph', () => {
  let tracer: Tracer;

  beforeEach(() => { tracer = new Tracer('./logs/test-tracer.jsonl'); });

  function makeRecord(overrides: Partial<ToolCallRecord> = {}): ToolCallRecord {
    return {
      id: `call_${Date.now()}_${Math.random().toString(36).slice(2,5)}`,
      timestamp: Date.now(), agentId: 'main-agent', toolName: 'fs.read',
      toolArgs: { path: '/test/file.txt' }, isSuspicious: false,
      sourceAttribution: { type: 'user_input', sourceId: 'msg-1', sourceSnippet: '' },
      ...overrides,
    };
  }

  it('should record tool calls', () => {
    tracer.record(makeRecord());
    tracer.record(makeRecord({ toolName: 'fs.write' }));
    expect(tracer.getAllRecords()).toHaveLength(2);
  });

  it('should filter suspicious records', () => {
    tracer.record(makeRecord({ isSuspicious: false }));
    tracer.record(makeRecord({ toolName: 'exec', isSuspicious: true }));
    tracer.record(makeRecord({ toolName: 'net.fetch', isSuspicious: true }));
    expect(tracer.getSuspiciousRecords()).toHaveLength(2);
  });

  it('should build DAG from records', () => {
    tracer.record(makeRecord({ agentId: 'main' }));
    tracer.record(makeRecord({ agentId: 'sub-1', parentAgentId: 'main' }));
    tracer.record(makeRecord({ agentId: 'sub-1', parentAgentId: 'main', toolName: 'exec' }));
    const graph = tracer.buildGraph();
    expect(graph.totalNodes).toBe(3);
  });

  it('should identify attack source nodes', () => {
    tracer.record(makeRecord({ agentId: 'main', toolName: 'fs.read' }));
    tracer.record(makeRecord({
      agentId: 'main', toolName: 'net.fetch', isSuspicious: true,
      sourceAttribution: { type: 'external_resource', sourceId: 'pr-42', sourceSnippet: '' },
    }));
    const graph = tracer.buildGraph();
    expect(graph.attackSources.length).toBeGreaterThanOrEqual(1);
  });

  it('should trace full attack path', () => {
    tracer.record(makeRecord({ agentId: 'main', isSuspicious: true,
      sourceAttribution: { type: 'external_resource', sourceId: 'pr-42', sourceSnippet: '' } }));
    tracer.record(makeRecord({ agentId: 'sub', parentAgentId: 'main', toolName: 'net.fetch', isSuspicious: true }));
    const graph = tracer.buildGraph();
    expect(graph.attackSources.length).toBeGreaterThan(0);
    if (graph.attackSources.length > 0) {
      const path = tracer.traceAttackPath(graph.attackSources[0]);
      expect(path.length).toBeGreaterThan(0);
    }
  });

  it('should summarize impacted resources', () => {
    tracer.record(makeRecord({ toolName: 'fs.read', isSuspicious: true, toolArgs: { path: '/home/user/.env' } }));
    tracer.record(makeRecord({ toolName: 'net.fetch', isSuspicious: true, toolArgs: { url: 'evil.com' } }));
    const graph = tracer.buildGraph();
    expect(graph.impactedResources.files.length).toBeGreaterThan(0);
    expect(graph.impactedResources.networkTargets.length).toBeGreaterThan(0);
  });

  it('should return stats', () => {
    tracer.record(makeRecord({ toolName: 'fs.read' }));
    tracer.record(makeRecord({ toolName: 'fs.read' }));
    tracer.record(makeRecord({ toolName: 'exec', isSuspicious: true }));
    const stats = tracer.stats();
    expect(stats.total).toBe(3);
    expect(stats.suspicious).toBe(1);
  });
});

// ===== DagRenderer =====
describe('DagRenderer', () => {
  function makeGraph(): CallGraph {
    return {
      rootNode: {
        id: 'n1', record: {
          id: 'r1', timestamp: Date.now(), agentId: 'main', toolName: 'fs.read',
          toolArgs: {}, isSuspicious: false,
          sourceAttribution: { type: 'user_input', sourceId: '1', sourceSnippet: '' },
        },
        children: [{
          id: 'n2', record: {
            id: 'r2', timestamp: Date.now(), agentId: 'sub', toolName: 'net.fetch',
            toolArgs: { url: 'evil.com' }, isSuspicious: true,
            sourceAttribution: { type: 'mcp_response', sourceId: '2', sourceSnippet: '' },
          },
          children: [], isAttackSource: true, isAnomalous: true,
        }],
        isAttackSource: false, isAnomalous: false,
      },
      totalNodes: 2, suspiciousNodes: 1, attackSources: [],
      impactedResources: { files: [], networkTargets: [], gitRepos: [], credentials: [] },
    };
  }

  it('should render valid Mermaid', () => {
    const r = new DagRenderer();
    const m = r.render(makeGraph(), { format: 'mermaid', highlightAnomalousNodes: true, showTimestamps: false, showSourceAttribution: true });
    expect(m).toContain('graph LR');
    expect(m).toContain('-->');
  });

  it('should render valid JSON', () => {
    const r = new DagRenderer();
    const j = r.render(makeGraph(), { format: 'json', highlightAnomalousNodes: false, showTimestamps: false, showSourceAttribution: false });
    const p = JSON.parse(j);
    expect(p.totalNodes).toBe(2);
  });
});

// ===== AuditLogger =====
describe('AuditLogger', () => {
  const LOG = './logs/test-audit.jsonl';

  it('should write audit logs to file', async () => {
    const logger = new AuditLogger(LOG);
    const sid = 'test-' + Date.now();

    await logger.log({ level: 'DETECTION', sessionId: sid, agentId: 'main', data: { type: 'direct', confidence: 0.95 } });
    await logger.log({ level: 'DECISION', sessionId: sid, agentId: 'main', data: { action: 'BLOCK', riskScore: 90 } });
    logger.close();

    const content = fs.readFileSync(LOG, 'utf-8');
    expect(content).toContain(sid);
    expect(content).toContain('DETECTION');
    expect(content).toContain('BLOCK');
  });

  it('should generate markdown report', async () => {
    const logger = new AuditLogger(LOG);
    const sid = 'report-' + Date.now();

    await logger.log({ level: 'DETECTION', sessionId: sid, agentId: 'main', data: { type: 'direct' } });
    await logger.log({ level: 'DECISION', sessionId: sid, agentId: 'main', data: { action: 'BLOCK' } });
    logger.close();

    const logger2 = new AuditLogger(LOG);
    const report = await logger2.generateReport(sid);
    expect(report).toContain('# 审计报告');
    expect(report).toContain(sid);
    logger2.close();
  });
});
