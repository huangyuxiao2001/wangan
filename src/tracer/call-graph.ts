/**
 * 调用链图谱构建器
 * 负责人：C
 *
 * 职责：
 *   - 记录全量工具调用及调用关系
 *   - 构建攻击路径 DAG（有向无环图）
 *   - 标记攻击触发源、上下文来源、影响范围
 */

export interface ToolCallRecord {
  id: string;
  timestamp: number;
  agentId: string;
  parentAgentId?: string;
  toolName: string;
  toolArgs: Record<string, unknown>;
  toolResult?: string;
  isSuspicious: boolean;
  suspicionReason?: string;
  sourceAttribution: {
    type: 'user_input' | 'external_resource' | 'memory' | 'mcp_response' | 'tool_description';
    sourceId: string;
    sourceSnippet: string;
  };
}

export interface CallGraphNode {
  id: string;
  record: ToolCallRecord;
  children: CallGraphNode[];
  isAttackSource: boolean;
  isAnomalous: boolean;
}

export interface CallGraph {
  rootNode: CallGraphNode;
  totalNodes: number;
  suspiciousNodes: number;
  attackSources: CallGraphNode[];
  impactedResources: {
    files: string[];
    networkTargets: string[];
    gitRepos: string[];
    credentials: string[];
  };
}

export class Tracer {
  private records: ToolCallRecord[] = [];
  private auditLogPath: string;

  constructor(auditLogPath: string) {
    this.auditLogPath = auditLogPath;
  }

  /**
   * 记录一次工具调用
   */
  record(call: ToolCallRecord): void {
    this.records.push(call);
  }

  /**
   * 批量记录
   */
  recordAll(calls: ToolCallRecord[]): void {
    this.records.push(...calls);
  }

  /**
   * 获取所有记录
   */
  getAllRecords(): ToolCallRecord[] {
    return [...this.records];
  }

  /**
   * 获取可疑记录
   */
  getSuspiciousRecords(): ToolCallRecord[] {
    return this.records.filter(r => r.isSuspicious);
  }

  /**
   * 构建调用链 DAG
   * 根据 agentId/parentAgentId 构建父子关系
   */
  buildGraph(): CallGraph {
    if (this.records.length === 0) {
      return this.emptyGraph();
    }

    // 步骤 1：按时间排序
    const sorted = [...this.records].sort((a, b) => a.timestamp - b.timestamp);

    // 步骤 2：建立 agentId → 节点映射
    const nodeMap = new Map<string, CallGraphNode>();
    const nodes: CallGraphNode[] = [];

    for (const record of sorted) {
      const node: CallGraphNode = {
        id: record.id,
        record,
        children: [],
        isAttackSource: false,
        isAnomalous: record.isSuspicious,
      };
      nodeMap.set(record.agentId, node);
      nodes.push(node);
    }

    // 步骤 3：根据 parentAgentId 连接父子关系
    const rootNodes: CallGraphNode[] = [];

    for (const node of nodes) {
      const parentId = node.record.parentAgentId;
      if (parentId && nodeMap.has(parentId)) {
        nodeMap.get(parentId)!.children.push(node);
      } else {
        rootNodes.push(node);
      }
    }

    // 步骤 4：标记攻击源节点
    const attackSources: CallGraphNode[] = [];
    for (const node of nodes) {
      // 攻击源 = 间接注入或记忆污染的首次出现
      if (
        node.record.isSuspicious &&
        (node.record.sourceAttribution.type === 'external_resource' ||
         node.record.sourceAttribution.type === 'memory' ||
         node.record.sourceAttribution.type === 'mcp_response')
      ) {
        node.isAttackSource = true;
        attackSources.push(node);
      }
    }

    // 步骤 5：汇总影响范围
    const impactedResources = this.summarizeImpact(nodes.filter(n => n.isAnomalous));

    // 构建根节点
    const rootNode: CallGraphNode = rootNodes.length === 1
      ? rootNodes[0]
      : {
          id: 'root',
          record: {
            id: 'root',
            timestamp: sorted[0]?.timestamp ?? Date.now(),
            agentId: 'root',
            toolName: '[Session Start]',
            toolArgs: {},
            isSuspicious: false,
            sourceAttribution: {
              type: 'user_input',
              sourceId: 'session',
              sourceSnippet: 'Session start',
            },
          },
          children: rootNodes,
          isAttackSource: false,
          isAnomalous: false,
        };

    return {
      rootNode,
      totalNodes: nodes.length,
      suspiciousNodes: nodes.filter(n => n.isAnomalous).length,
      attackSources,
      impactedResources,
    };
  }

  /**
   * 沿攻击链路溯源
   * 从攻击源节点出发，BFS 追踪所有下游影响
   */
  traceAttackPath(sourceNode: CallGraphNode): CallGraphNode[] {
    const visited = new Set<string>();
    const path: CallGraphNode[] = [];
    const queue: CallGraphNode[] = [sourceNode];

    while (queue.length > 0) {
      const node = queue.shift()!;
      if (visited.has(node.id)) continue;
      visited.add(node.id);
      path.push(node);

      for (const child of node.children) {
        queue.push(child);
      }
    }

    return path;
  }

  /**
   * 查找攻击触发源
   * @returns 所有被标记为攻击源的节点
   */
  findAttackSources(): CallGraphNode[] {
    const graph = this.buildGraph();
    return graph.attackSources;
  }

  /**
   * 汇总影响范围
   */
  private summarizeImpact(anomalousNodes: CallGraphNode[]): CallGraph['impactedResources'] {
    const files = new Set<string>();
    const networkTargets = new Set<string>();
    const gitRepos = new Set<string>();
    const credentials = new Set<string>();

    const sensitiveFilePatterns = ['.env', '.pem', '.key', 'credentials', 'id_rsa', 'token', 'secret', '.ssh/', '.aws/'];

    for (const node of anomalousNodes) {
      const args = node.record.toolArgs;

      // 文件操作
      const path = (args.path ?? args.filePath ?? args.target_path ?? args.file) as string | undefined;
      if (path) {
        const pathStr = String(path);
        files.add(pathStr);

        // 检测是否为凭据类文件
        for (const pattern of sensitiveFilePatterns) {
          if (pathStr.toLowerCase().includes(pattern)) {
            credentials.add(pathStr);
            break;
          }
        }
      }

      // 网络目标
      const url = (args.url ?? args.target_url) as string | undefined;
      if (url) {
        try {
          const hostname = new URL(String(url).startsWith('http') ? String(url) : `https://${String(url)}`).hostname;
          networkTargets.add(hostname);
        } catch {
          networkTargets.add(String(url));
        }
      }

      // Git 操作
      if (node.record.toolName.startsWith('git.')) {
        const remote = args.remote as string | undefined;
        const repo = args.repo as string | undefined;
        if (remote) gitRepos.add(String(remote));
        if (repo) gitRepos.add(String(repo));
      }
    }

    return {
      files: [...files],
      networkTargets: [...networkTargets],
      gitRepos: [...gitRepos],
      credentials: [...credentials],
    };
  }

  /**
   * 清空当前会话记录
   */
  clear(): void {
    this.records = [];
  }

  /**
   * 获取统计信息
   */
  stats(): { total: number; suspicious: number; byTool: Record<string, number> } {
    const byTool: Record<string, number> = {};
    let suspicious = 0;

    for (const record of this.records) {
      byTool[record.toolName] = (byTool[record.toolName] ?? 0) + 1;
      if (record.isSuspicious) suspicious++;
    }

    return {
      total: this.records.length,
      suspicious,
      byTool,
    };
  }

  private emptyGraph(): CallGraph {
    return {
      rootNode: {
        id: 'empty',
        record: {
          id: 'empty',
          timestamp: Date.now(),
          agentId: 'root',
          toolName: '[No Activity]',
          toolArgs: {},
          isSuspicious: false,
          sourceAttribution: {
            type: 'user_input',
            sourceId: 'session',
            sourceSnippet: 'No activity recorded',
          },
        },
        children: [],
        isAttackSource: false,
        isAnomalous: false,
      },
      totalNodes: 0,
      suspiciousNodes: 0,
      attackSources: [],
      impactedResources: {
        files: [],
        networkTargets: [],
        gitRepos: [],
        credentials: [],
      },
    };
  }
}
