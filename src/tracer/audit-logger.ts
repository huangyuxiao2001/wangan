/**
 * 审计日志记录器
 * 负责人：C
 *
 * 职责：
 *   - 结构化 JSON 日志输出（JSON Lines 格式，每行一条）
 *   - SQLite 持久化存储（用于长期审计和查询）
 *   - 统一日志格式，供所有子任务使用
 *
 * 日志类型：
 *   - DETECTION  — 注入检测结果
 *   - DECISION   — 策略决策结果
 *   - TOOL_CALL  — 工具调用详情
 *   - TRACE      — 溯源链路信息
 *   - ERROR      — 系统错误
 */

import * as fs from 'fs';
import * as path from 'path';

export type AuditLogLevel = 'DETECTION' | 'DECISION' | 'TOOL_CALL' | 'TRACE' | 'ERROR';

export interface AuditLogEntry {
  id: string;
  timestamp: number;
  level: AuditLogLevel;
  sessionId: string;
  agentId: string;
  data: Record<string, unknown>;
  metadata: {
    sourceFile?: string;
    version: string;
  };
}

export class AuditLogger {
  private logPath: string;
  private writeStream: fs.WriteStream | null = null;
  private sqliteAvailable = false;

  constructor(logPath: string) {
    this.logPath = logPath;

    // 确保日志目录存在
    const dir = path.dirname(logPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // 尝试加载 SQLite
    try {
      require('better-sqlite3');
      this.sqliteAvailable = true;
    } catch {
      // SQLite 不可用，仅使用文件日志
      this.sqliteAvailable = false;
    }

    // 打开文件写入流（追加模式）
    this.writeStream = fs.createWriteStream(logPath, { flags: 'a' });
  }

  /**
   * 记录审计日志
   */
  async log(entry: Omit<AuditLogEntry, 'id' | 'timestamp' | 'metadata'>): Promise<void> {
    const fullEntry: AuditLogEntry = {
      id: this.generateId(),
      timestamp: Date.now(),
      metadata: { version: '1.0.0' },
      ...entry,
    };

    // 写入 JSON Lines 文件
    this.writeToFile(fullEntry);

    // 写入控制台（开发模式）
    if (entry.level === 'ERROR') {
      console.error(`[Audit:${entry.level}] ${JSON.stringify(fullEntry.data).slice(0, 200)}`);
    }
  }

  /**
   * 记录注入检测结果
   */
  async logDetection(sessionId: string, detection: Record<string, unknown>): Promise<void> {
    await this.log({
      level: 'DETECTION',
      sessionId,
      agentId: detection.agentId as string ?? 'main-agent',
      data: detection,
    });
  }

  /**
   * 记录决策结果
   */
  async logDecision(sessionId: string, decision: Record<string, unknown>): Promise<void> {
    await this.log({
      level: 'DECISION',
      sessionId,
      agentId: 'main-agent',
      data: decision,
    });
  }

  /**
   * 记录工具调用
   */
  async logToolCall(sessionId: string, toolCall: Record<string, unknown>): Promise<void> {
    await this.log({
      level: 'TOOL_CALL',
      sessionId,
      agentId: toolCall.agentId as string ?? 'main-agent',
      data: toolCall,
    });
  }

  /**
   * 记录错误
   */
  async logError(sessionId: string, error: Error | string, context?: Record<string, unknown>): Promise<void> {
    await this.log({
      level: 'ERROR',
      sessionId,
      agentId: 'system',
      data: {
        error: error instanceof Error ? error.message : error,
        stack: error instanceof Error ? error.stack : undefined,
        context: context ?? {},
      },
    });
  }

  /**
   * 按时间范围查询审计日志
   * 先从 JSONL 文件中读取（兼容方案）
   */
  async query(options: {
    startTime?: number;
    endTime?: number;
    level?: AuditLogLevel;
    sessionId?: string;
    agentId?: string;
    limit?: number;
  }): Promise<AuditLogEntry[]> {
    const results: AuditLogEntry[] = [];
    const limit = options.limit ?? 100;

    try {
      // 先 flush 写入流，确保数据已落盘
      if (this.writeStream) {
        this.writeStream.end();
        this.writeStream = fs.createWriteStream(this.logPath, { flags: 'a' });
      }

      // 读取 JSONL 文件
      if (!fs.existsSync(this.logPath)) return [];

      const content = fs.readFileSync(this.logPath, 'utf-8');
      const lines = content.trim().split('\n');

      for (const line of lines.reverse()) {
        if (results.length >= limit) break;

        try {
          const entry = JSON.parse(line) as AuditLogEntry;

          // 过滤
          if (options.startTime && entry.timestamp < options.startTime) continue;
          if (options.endTime && entry.timestamp > options.endTime) continue;
          if (options.level && entry.level !== options.level) continue;
          if (options.sessionId && entry.sessionId !== options.sessionId) continue;
          if (options.agentId && entry.agentId !== options.agentId) continue;

          results.push(entry);
        } catch {
          // skip malformed lines
        }
      }
    } catch (e) {
      console.error(`[AuditLogger] Query error:`, e);
    }

    return results;
  }

  /**
   * 生成审计报告（Markdown 格式）
   */
  async generateReport(sessionId: string): Promise<string> {
    const entries = await this.query({ sessionId, limit: 1000 });

    if (entries.length === 0) {
      return `# 审计报告\n\n> 会话: ${sessionId}\n\n无审计记录。`;
    }

    // 分类统计
    const byLevel: Record<string, number> = {};
    const detections = entries.filter(e => e.level === 'DETECTION');
    const decisions = entries.filter(e => e.level === 'DECISION');
    const toolCalls = entries.filter(e => e.level === 'TOOL_CALL');
    const blocks = decisions.filter(d => d.data.action === 'BLOCK').length;
    const asks = decisions.filter(d => d.data.action === 'ASK_USER').length;
    const allows = decisions.filter(d => d.data.action === 'ALLOW').length;

    for (const e of entries) {
      byLevel[e.level] = (byLevel[e.level] ?? 0) + 1;
    }

    const timeRange = entries.length > 1
      ? new Date(entries[entries.length - 1].timestamp).toISOString() + ' — ' +
        new Date(entries[0].timestamp).toISOString()
      : 'N/A';

    const lines = [
      '# 审计报告',
      '',
      `> **会话ID**: \`${sessionId}\``,
      `> **时间范围**: ${timeRange}`,
      `> **总记录数**: ${entries.length}`,
      '',
      '## 统计概览',
      '',
      '| 指标 | 数量 |',
      '|------|------|',
      `| 注入检测 | ${detections.length} |`,
      `| 策略决策 | ${decisions.length} |`,
      `| 工具调用 | ${toolCalls.length} |`,
      `| 阻断次数 | ${blocks} |`,
      `| 询问次数 | ${asks} |`,
      `| 放行次数 | ${allows} |`,
      '',
      '## 阻断事件',
      '',
    ];

    const blockedEvents = decisions.filter(d => d.data.action === 'BLOCK');
    if (blockedEvents.length > 0) {
      for (const event of blockedEvents) {
        lines.push(`- **${new Date(event.timestamp).toISOString()}**: ${event.data.explanation ?? 'No explanation'}`);
        lines.push(`  - 风险评分: ${event.data.riskScore ?? 'N/A'}`);
        lines.push(`  - 触发策略: \`${event.data.matchedPolicyId ?? 'N/A'}\``);
        lines.push('');
      }
    } else {
      lines.push('无阻断事件。');
    }

    lines.push('');
    lines.push('## 完整日志（按时间倒序）');
    lines.push('');
    lines.push('| 时间 | 级别 | 摘要 |');
    lines.push('|------|------|------|');
    for (const entry of entries.slice(0, 100)) {
      const time = new Date(entry.timestamp).toISOString().slice(11, 23);
      const summary = JSON.stringify(entry.data).slice(0, 80);
      lines.push(`| ${time} | ${entry.level} | ${summary} |`);
    }

    return lines.join('\n');
  }

  /**
   * 关闭日志写入流
   */
  close(): void {
    if (this.writeStream) {
      this.writeStream.end();
      this.writeStream = null;
    }
  }

  // ---- 私有方法 ----

  private writeToFile(entry: AuditLogEntry): void {
    // Use synchronous append for immediate persistence (needed for tests)
    try {
      fs.appendFileSync(this.logPath, JSON.stringify(entry) + '\n');
    } catch {
      // fallback to stream
      if (this.writeStream) {
        this.writeStream.write(JSON.stringify(entry) + '\n');
      }
    }
  }

  private generateId(): string {
    return `audit_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
  }
}
