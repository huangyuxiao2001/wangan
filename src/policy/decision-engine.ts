/**
 * 策略决策引擎
 * 负责人：B
 *
 * 职责：
 *   - 综合注入检测结果 + 意图偏离度 + 策略规则 → 输出三态决策
 *   - 这是整个安全管道的决策汇聚点
 *
 * 决策矩阵：
 *   | 注入检测 | 偏离度   | 策略匹配    | 决策      | 风险评分 |
 *   |---------|---------|------------|----------|---------|
 *   | 无       | <0.3    | 无         | ALLOW    | <20     |
 *   | 不确定    | 0.3-0.6 | LOW        | ASK_USER | 20-50   |
 *   | 有       | >0.6    | CRITICAL   | BLOCK    | >80     |
 *   | 有       | 任意     | HIGH+      | BLOCK    | >60     |
 *   | 不确定    | >0.6    | MEDIUM+    | BLOCK    | >50     |
 */

import { DetectionResult } from '../detector/detection-engine';
import { DeviationReport } from '../aligner/deviation-scorer';
import { EvaluationResult } from './rule-evaluator';

export interface DecisionResult {
  action: 'ALLOW' | 'ASK_USER' | 'BLOCK';
  riskScore: number;
  deviationScore: number;
  matchedPolicyId?: string;
  explanation: string;
  details: {
    detectionConfidence: number;
    deviationOverall: number;
    policyRisk: string;
  };
}

export class DecisionEngine {
  /**
   * 综合决策主入口
   *
   * @param detection 注入检测结果（子任务 A）
   * @param deviation 意图偏离度报告（子任务 B）
   * @param policyEval 策略评估结果（子任务 B）
   * @returns 最终决策
   */
  evaluate(
    detection: DetectionResult,
    deviation: DeviationReport,
    policyEval: EvaluationResult
  ): DecisionResult {
    const devScore = deviation.overallScore;

    // ---- 步骤 1：决策矩阵判定 ----

    // 规则 0：极高置信度注入 → 直接阻断（无需策略匹配）
    if (detection.isInjection && detection.confidence >= 0.95) {
      const riskScore = this.computeRiskScore(detection.confidence, devScore, policyEval.matchedRule);
      return this.buildResult(
        'BLOCK',
        riskScore,
        devScore,
        policyEval.matchedRule?.id,
        this.buildExplanation(detection, deviation, policyEval, 'BLOCK'),
        detection, deviation, policyEval
      );
    }

    // 规则 4：策略匹配到 HIGH 或 CRITICAL → 直接阻断
    if (policyEval.matched && policyEval.matchedRule) {
      const risk = policyEval.matchedRule.risk;
      if (risk === 'CRITICAL' || risk === 'HIGH') {
        const riskScore = this.computeRiskScore(detection.confidence, devScore, policyEval.matchedRule);
        return this.buildResult(
          'BLOCK',
          riskScore,
          devScore,
          policyEval.matchedRule.id,
          this.buildExplanation(detection, deviation, policyEval, 'BLOCK'),
          detection, deviation, policyEval
        );
      }
    }

    // 规则 3：高置信度注入 + 高偏离度 → 阻断
    if (detection.isInjection && detection.confidence > 0.8 && devScore > 0.6) {
      const riskScore = this.computeRiskScore(detection.confidence, devScore, policyEval.matchedRule);
      return this.buildResult(
        'BLOCK',
        riskScore,
        devScore,
        policyEval.matchedRule?.id,
        this.buildExplanation(detection, deviation, policyEval, 'BLOCK'),
        detection, deviation, policyEval
      );
    }

    // 规则 5：不确定 + 高偏离度 + 有策略匹配 → 阻断
    if (detection.confidence > 0.5 && devScore > 0.6 && policyEval.matched) {
      const riskScore = this.computeRiskScore(detection.confidence, devScore, policyEval.matchedRule);
      return this.buildResult(
        'BLOCK',
        riskScore,
        devScore,
        policyEval.matchedRule?.id,
        this.buildExplanation(detection, deviation, policyEval, 'BLOCK'),
        detection, deviation, policyEval
      );
    }

    // 规则 1：无注入 + 低偏离度 → 放行
    if (!detection.isInjection && devScore < 0.3 && !policyEval.matched) {
      return this.buildResult(
        'ALLOW',
        this.computeRiskScore(detection.confidence, devScore),
        devScore,
        undefined,
        '操作正常，未检测到注入攻击或意图偏离。',
        detection, deviation, policyEval
      );
    }

    // 规则 2：不确定 → 询问用户
    if ((detection.isInjection && detection.confidence < 0.8) ||
        (devScore >= 0.3 && devScore <= 0.6) ||
        (policyEval.matched && policyEval.matchedRule?.risk === 'MEDIUM')) {

      const risk = detection.confidence < 0.5 ? 'MEDIUM' : 'HIGH';
      const riskScore = this.computeRiskScore(detection.confidence, devScore, policyEval.matchedRule);
      const rule = policyEval.matchedRule;

      return this.buildResult(
        'ASK_USER',
        riskScore,
        devScore,
        rule?.id,
        this.buildExplanation(detection, deviation, policyEval, 'ASK_USER'),
        detection, deviation, policyEval
      );
    }

    // 默认：放行
    return this.buildResult(
      'ALLOW',
      this.computeRiskScore(detection.confidence, devScore),
      devScore,
      policyEval.matchedRule?.id,
      '未匹配安全策略，默认放行。',
      detection, deviation, policyEval
    );
  }

  /**
   * 生成询问用户时的风险提示
   */
  generateUserPrompt(decision: DecisionResult): string {
    const lines = [
      '⚠️ **安全风险提示**',
      '',
      `**风险等级**: ${decision.riskScore}/100`,
      `**偏离度**: ${(decision.deviationScore * 100).toFixed(0)}%`,
    ];

    if (decision.matchedPolicyId) {
      lines.push(`**触发策略**: \`${decision.matchedPolicyId}\``);
    }

    lines.push('');
    lines.push(`**详情**: ${decision.explanation}`);
    lines.push('');
    lines.push('请确认是否继续执行此操作：');
    lines.push('- 回复 **"允许"** 继续执行');
    lines.push('- 回复 **"拒绝"** 或直接忽略将自动阻断此操作');

    return lines.join('\n');
  }

  /**
   * 构建决策结果
   */
  private buildResult(
    action: DecisionResult['action'],
    riskScore: number,
    deviationScore: number,
    policyId: string | undefined,
    explanation: string,
    detection: DetectionResult,
    deviation: DeviationReport,
    policyEval: EvaluationResult
  ): DecisionResult {
    return {
      action,
      riskScore: Math.min(Math.round(riskScore), 100),
      deviationScore,
      matchedPolicyId: policyId,
      explanation,
      details: {
        detectionConfidence: detection.confidence,
        deviationOverall: deviation.overallScore,
        policyRisk: policyEval.matchedRule?.risk ?? 'NONE',
      },
    };
  }

  /**
   * 生成可解释研判结论
   */
  private buildExplanation(
    detection: DetectionResult,
    deviation: DeviationReport,
    policyEval: EvaluationResult,
    action: string
  ): string {
    const parts: string[] = [];

    // 注入检测结论
    if (detection.isInjection) {
      parts.push(
        `检测到 ${detection.injectionType === 'direct' ? '直接' :
                     detection.injectionType === 'indirect' ? '间接' :
                     detection.injectionType === 'memory_poisoning' ? '记忆污染' : '未知'} ` +
        `注入攻击（置信度：${(detection.confidence * 100).toFixed(0)}%）`
      );

      if (detection.payloadSnippet) {
        parts.push(`攻击载荷：\`${detection.payloadSnippet.slice(0, 100)}\``);
      }
    }

    // 偏离度结论
    if (deviation.overallScore > 0.3) {
      parts.push(
        `意图偏离度评分：${(deviation.overallScore * 100).toFixed(0)}%（` +
        `目标偏离 ${(deviation.dimensionScores.goalDeviation * 100).toFixed(0)}%、` +
        `范围偏离 ${(deviation.dimensionScores.scopeDeviation * 100).toFixed(0)}%、` +
        `工具偏离 ${(deviation.dimensionScores.toolDeviation * 100).toFixed(0)}%、` +
        `数据流偏离 ${(deviation.dimensionScores.dataFlowDeviation * 100).toFixed(0)}%）`
      );
    }

    // 策略命中
    if (policyEval.matchedRule) {
      parts.push(`命中策略：${policyEval.matchedRule.id}（${policyEval.matchedRule.message}）`);
    }

    // 决策
    const actionLabel = action === 'BLOCK' ? '阻断' : action === 'ASK_USER' ? '需要用户确认' : '放行';
    parts.push(`决策：${actionLabel}`);

    return parts.join('。');
  }

  /**
   * 计算综合风险评分
   */
  private computeRiskScore(
    confidence: number,
    deviationScore: number,
    matchedRule?: { risk: string }
  ): number {
    const riskWeight: Record<string, number> = { 'CRITICAL': 100, 'HIGH': 75, 'MEDIUM': 50, 'LOW': 25 };

    let score = confidence * 40 + deviationScore * 40;

    if (matchedRule) {
      score += (riskWeight[matchedRule.risk] ?? 0) * 0.2;
    }

    return Math.round(Math.min(score, 100));
  }
}
