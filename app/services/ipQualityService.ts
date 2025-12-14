import type { IPQualityResult } from "../types/ipQuality";

// ============ 环境变量 ============
const IPQS_KEY = process.env.IPQS_KEY || "";
const ABUSEIPDB_KEY = process.env.ABUSEIPDB_KEY || "";
const IP2LOCATION_KEY = process.env.IP2LOCATION_KEY || "";
const IPDATA_KEY = process.env.IPDATA_KEY || "";
const CLOUDFLARE_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN || "";
const LLM_API_KEY = process.env.LLM_API_KEY || "";
const LLM_BASE_URL = process.env.LLM_BASE_URL || "";
const LLM_MODEL = process.env.LLM_MODEL || "gpt-3.5-turbo";

// ============ 内联工具函数 ============

const cache = new Map<string, { data: IPQualityResult; expires: number }>();

function cacheGet(key: string): IPQualityResult | null {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expires) {
    cache.delete(key);
    return null;
  }
  return entry.data;
}

function cacheSet(key: string, data: IPQualityResult, ttlSeconds: number): void {
  cache.set(key, { data, expires: Date.now() + ttlSeconds * 1000 });
}

async function fetchWithTimeout(
  url: string,
  timeoutMs: number,
  options?: { headers?: Record<string, string>; params?: Record<string, string> }
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  let finalUrl = url;
  if (options?.params) {
    const searchParams = new URLSearchParams(options.params);
    finalUrl += (url.includes("?") ? "&" : "?") + searchParams.toString();
  }

  try {
    const response = await fetch(finalUrl, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        ...options?.headers,
      },
    });
    return response;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function analyzeWithLLM(
  data: Record<string, unknown>,
  ip: string
): Promise<{ reasoning: string }> {
  if (!LLM_API_KEY || !LLM_BASE_URL) {
    console.log("[LLM] 未配置 API Key 或 Base URL");
    return { reasoning: "" };
  }

  const prompt = `Analyze the following IP quality data and provide a professional risk assessment report:

IP: ${ip}
Key Metrics:
- Fraud Score: ${data.fraudScore || 'N/A'}
- Abuse Score: ${data.abuseScore || 'N/A'}
- IP Type: ${data.ipType || 'N/A'}
- VPN: ${data.isVpn || false}, Proxy: ${data.isProxy || false}, Tor: ${data.isTor || false}
- Hosting/Datacenter: ${data.isHosting || false}
- ASN Bot Traffic: ${data.cf_asn_bot_pct ? Number(data.cf_asn_bot_pct).toFixed(1) + '%' : 'N/A'}
- ISP: ${data.isp || 'N/A'}
- Country: ${data.countryCode || 'N/A'}

Please provide in Chinese (必须用中文回复):
1. IP类型判断和网络特征分析
2. 风险等级评估（低风险/中等风险/高风险）
3. 建议的使用场景和注意事项

Keep response concise, around 200-400 words.`;

  try {
    console.log(`[LLM] 调用 API: ${LLM_BASE_URL}/chat/completions, Model: ${LLM_MODEL}`);
    const response = await fetch(`${LLM_BASE_URL}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${LLM_API_KEY}`,
      },
      body: JSON.stringify({
        model: LLM_MODEL,
        messages: [{ role: "user", content: prompt }],
        max_tokens: 2000,
        temperature: 0.7,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`[LLM] API 返回错误 ${response.status}: ${errorText}`);
      return { reasoning: "" };
    }

    const result = await response.json() as { 
      choices?: Array<{ 
        message?: { content?: string }; 
        finish_reason?: string 
      }> 
    };
    const reasoning = result.choices?.[0]?.message?.content || "";
    const finishReason = result.choices?.[0]?.finish_reason;
    
    console.log(`[LLM] 分析完成，长度: ${reasoning.length}, finish_reason: ${finishReason}`);
    
    if (reasoning.length === 0) {
      console.warn(`[LLM] 返回内容为空，完整响应:`, JSON.stringify(result));
    }
    
    return { reasoning };
  } catch (error) {
    console.error(`[LLM] 调用失败:`, error);
    return { reasoning: "" };
  }
}

// ============ 类型定义 ============

type MergedResult = Record<string, unknown> & { sources: string[] };

// ============ 主服务类 ============

const API_TIMEOUT = 5000;

interface ApiConfig {
  name: string;
  url?: string;
  enabled: boolean;
  headers?: Record<string, string>;
  params?: Record<string, string>;
  requiresASN?: boolean;
  buildUrl?: (asn: string) => string;
  transform: (d: Record<string, unknown>) => Record<string, unknown>;
}

export class IPQualityService {
  async check(ip: string): Promise<IPQualityResult> {
    const cacheKey = `ip-quality:${ip}`;
    const cached = cacheGet(cacheKey);
    if (cached) {
      console.log(`[IPQuality] 使用缓存数据: ${ip}`);
      return cached;
    }

    console.log(`[IPQuality] 开始检测 IP: ${ip}`);
    console.log(`[IPQuality] 环境变量状态: IPQS=${Boolean(IPQS_KEY)}, ABUSEIPDB=${Boolean(ABUSEIPDB_KEY)}, IP2LOCATION=${Boolean(IP2LOCATION_KEY)}, IPDATA=${Boolean(IPDATA_KEY)}, CF=${Boolean(CLOUDFLARE_API_TOKEN)}`);

    const apis = this.buildApis(ip);
    const { regularApis, asnDependentApis } = this.partitionApis(apis);

    console.log(`[IPQuality] 启用的常规 API: ${regularApis.map(a => a.name).join(', ')}`);

    const phase1Results = await this.callApis(regularApis);
    const merged = this.mergeResults(phase1Results);

    const asn = (merged.asn || merged.ASN || merged.as) as string | undefined;
    console.log(`[IPQuality] 获取到 ASN: ${asn || '未获取到'}`);
    
    if (asn && asnDependentApis.length > 0) {
      console.log(`[IPQuality] 启用的 ASN 相关 API: ${asnDependentApis.map(a => a.name).join(', ')}`);
      const asnResults = await this.callApis(asnDependentApis, asn);
      phase1Results.push(...asnResults);
    }

    const mergedResult = this.mergeResults(phase1Results);
    console.log(`[IPQuality] 合并后的数据源: ${mergedResult.sources}`);
    
    const enhancedResult = await this.enhanceResult(mergedResult, ip);

    cacheSet(cacheKey, enhancedResult as IPQualityResult, 900);
    return enhancedResult as IPQualityResult;
  }

  private buildApis(ip: string): ApiConfig[] {
    return [
      {
        name: "ipqs",
        url: `https://www.ipqualityscore.com/api/json/ip/${IPQS_KEY}/${ip}`,
        enabled: Boolean(IPQS_KEY),
        transform: (d) => this.transformIPQS(d),
      },
      {
        name: "ipapi",
        url: `https://ipwho.is/${ip}`,
        enabled: true,
        transform: (d) => this.transformIPApi(d),
      },
      {
        name: "abuseipdb",
        url: "https://api.abuseipdb.com/api/v2/check",
        enabled: Boolean(ABUSEIPDB_KEY),
        headers: { Key: ABUSEIPDB_KEY, Accept: "application/json" },
        params: { ipAddress: ip, maxAgeInDays: "90" },
        transform: (d) => this.transformAbuseIPDB(d),
      },
      {
        name: "ip2location",
        url: "https://api.ip2location.io/",
        enabled: Boolean(IP2LOCATION_KEY),
        params: { key: IP2LOCATION_KEY, ip },
        transform: (d) => this.transformIP2Location(d),
      },
      {
        name: "ipdata",
        url: `https://api.ipdata.co/${ip}`,
        enabled: Boolean(IPDATA_KEY),
        params: { "api-key": IPDATA_KEY },
        transform: (d) => this.transformIPData(d),
      },
      {
        name: "cloudflare_asn",
        enabled: Boolean(CLOUDFLARE_API_TOKEN),
        requiresASN: true,
        buildUrl: (asn: string) => this.buildCloudflareURL(asn),
        headers: { Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}` },
        transform: (d) => this.transformCloudflare(d),
      },
    ];
  }

  private partitionApis(apis: ApiConfig[]) {
    const regularApis = apis.filter((api) => api.enabled && !api.requiresASN);
    const asnDependentApis = apis.filter((api) => api.enabled && api.requiresASN);
    return { regularApis, asnDependentApis };
  }

  private async callApis(apis: ApiConfig[], asn?: string) {
    const results = await Promise.allSettled(
      apis.map(async (api) => {
        try {
          const url = api.requiresASN && api.buildUrl ? api.buildUrl(asn!) : api.url!;
          console.log(`[IPQuality] 调用 ${api.name}: ${url}`);
          
          const response = await fetchWithTimeout(url, API_TIMEOUT, {
            headers: api.headers,
            params: api.params,
          });
          
          if (!response.ok) {
            const errorText = await response.text();
            console.error(`[IPQuality] ${api.name} 返回 ${response.status}: ${errorText.substring(0, 200)}`);
            throw new Error(`HTTP ${response.status}`);
          }
          
          const data = await response.json() as Record<string, unknown>;
          const transformed = api.transform(data);
          console.log(`[IPQuality] ${api.name} 成功，返回字段: ${Object.keys(transformed).join(', ')}`);
          
          return { source: api.name, data: transformed };
        } catch (error) {
          console.error(`[IPQuality] ${api.name} 失败:`, error);
          throw error;
        }
      })
    );

    return results
      .filter((result): result is PromiseFulfilledResult<{ source: string; data: Record<string, unknown> }> =>
        result.status === "fulfilled"
      )
      .map((result) => result.value);
  }

  private mergeResults(results: Array<{ source: string; data: Record<string, unknown> }>): MergedResult {
    const sources: string[] = [];
    const merged: Record<string, unknown> = {};
    
    // 对于 boolean 字段使用 OR 逻辑（任何一个为 true 则为 true）
    const booleanFields = ['isVpn', 'isProxy', 'isTor', 'isHosting', 'isMobile'];
    
    results.forEach(result => {
      sources.push(result.source);
      
      Object.entries(result.data).forEach(([key, value]) => {
        if (booleanFields.includes(key)) {
          merged[key] = merged[key] === true || value === true;
        } else {
          // 其他字段：后面的值覆盖前面的（除非当前值为 null/undefined）
          if (value !== null && value !== undefined) {
            merged[key] = value;
          }
        }
      });
    });
    
    return { ...merged, sources };
  }

  private async enhanceResult(data: MergedResult, ip: string) {
    const isNative = this.determineNative(data);
    const isDualIsp = this.determineDualISP(data);

    const result = {
      ip,
      ...data,
      isNative,
      isDualIsp,
      ipType: this.determineIPType(data),
      timestamp: new Date().toISOString(),
    };

    if (LLM_API_KEY && LLM_BASE_URL) {
      const aiResult = await analyzeWithLLM(result, ip);
      return { ...result, aiReasoning: aiResult.reasoning };
    }

    return result;
  }

  private determineNative(data: Record<string, unknown>) {
    const geoCountry = data.countryCode || data.country_code;
    const ip2locCountry = data.ip2location_country_code;
    return geoCountry && ip2locCountry ? geoCountry === ip2locCountry : true;
  }

  private determineDualISP(data: Record<string, unknown>) {
    return data.isp && data.org && data.isp !== data.org;
  }

  private determineIPType(data: Record<string, unknown>): string {
    // 优先使用明确的类型信息（避免 "Premium required."）
    
    // 1. 优先使用 AbuseIPDB 的 usageType（最详细）
    if (data.usageType && typeof data.usageType === 'string' && !data.usageType.includes('Premium')) {
      return data.usageType as string;
    }
    
    // 2. 使用 IP2Location 的 usageType
    if (data.ip2location_usage_type && typeof data.ip2location_usage_type === 'string') {
      return data.ip2location_usage_type as string;
    }
    
    // 3. 使用 IPData 的 ASN type
    if (data.asn_type && typeof data.asn_type === 'string') {
      const asnType = data.asn_type as string;
      // 转换为友好的名称
      const typeMap: Record<string, string> = {
        'hosting': 'Data Center/Hosting',
        'isp': 'ISP/Residential',
        'business': 'Business',
        'education': 'Education/Research',
      };
      return typeMap[asnType.toLowerCase()] || asnType;
    }
    
    // 4. 使用 IPQS 的 connection_type（如果不是 Premium required）
    if (data.connection_type && typeof data.connection_type === 'string' && !data.connection_type.includes('Premium')) {
      return data.connection_type as string;
    }
    
    // 5. 根据 boolean 标记判断
    if (data.isHosting === true) return "Data Center/Hosting";
    if (data.isMobile === true) return "Mobile";
    if (data.isVpn === true || data.isProxy === true) return "VPN/Proxy";
    if (data.isTor === true) return "Tor Exit Node";
    
    // 6. 默认值
    return "Residential";
  }

  private transformIPQS(d: Record<string, unknown>) {
    return {
      fraudScore: d.fraud_score,
      isVpn: d.vpn,
      isProxy: d.proxy,
      isTor: d.tor,
      isHosting: Boolean(d.host),
      isMobile: d.mobile,
      connection_type: d.connection_type,
      isp: d.ISP,
      org: d.organization,
      asn: d.ASN,
      ASN: d.ASN,
    };
  }

  private transformIPApi(d: Record<string, unknown>) {
    return {
      countryCode: d.country_code,
      country: d.country_name,
      city: d.city,
      isp: d.isp,
      org: d.organisation || d.org,
      asn: d.asn,
      ASN: d.asn,
      as: d.asn,
    };
  }

  private transformAbuseIPDB(d: Record<string, unknown>) {
    const data = (d.data || {}) as Record<string, unknown>;
    return {
      abuseScore: data.abuseConfidenceScore,
      totalReports: data.totalReports,
      isWhitelisted: data.isWhitelisted,
      usageType: data.usageType,
      isp: data.isp,
      domain: data.domain,
    };
  }

  private transformIP2Location(d: Record<string, unknown>) {
    return {
      ip2location_country_code: d.country_code,
      ip2location_usage_type: d.usage_type,
      isProxy: d.is_proxy,
    };
  }

  private transformIPData(d: Record<string, unknown>) {
    const threat = (d.threat || {}) as Record<string, unknown>;
    const asn = (d.asn || {}) as Record<string, unknown>;
    return {
      isTor: threat.is_tor,
      isProxy: threat.is_proxy,
      isAnonymous: threat.is_anonymous,
      isKnownAbuser: threat.is_known_abuser,
      isKnownAttacker: threat.is_known_attacker,
      isThreat: threat.is_threat,
      asn_type: asn.type,
    };
  }

  private transformCloudflare(d: Record<string, unknown>) {
    console.log(`[IPQuality] Cloudflare 原始响应:`, JSON.stringify(d).substring(0, 500));
    const result = (d.result || {}) as Record<string, unknown>;
    const summary = (result.summary_0 || result.summary || {}) as Record<string, unknown>;
    
    if (!summary.bot && !summary.human) {
      console.warn(`[IPQuality] Cloudflare 未返回 bot/human 数据，完整响应:`, JSON.stringify(d));
    }
    
    return {
      cf_asn_bot_pct: summary.bot,
      cf_asn_human_pct: summary.human,
      cf_asn_likely_bot: Number(summary.bot || 0) > 50,
    };
  }

  private buildCloudflareURL(asn: string) {
    const match = asn.toString().match(/\d+/);
    if (!match) {
      console.error(`[IPQuality] 无效的 ASN 格式: ${asn}`);
      throw new Error(`Invalid ASN format: ${asn}`);
    }
    const url = `https://api.cloudflare.com/client/v4/radar/http/summary/bot_class?asn=${match[0]}&dateRange=7d&format=json`;
    console.log(`[IPQuality] Cloudflare URL: ${url}`);
    return url;
  }
}