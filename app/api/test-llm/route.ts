import { NextResponse } from "next/server";

export const runtime = "edge";

export async function GET() {
  const LLM_API_KEY = process.env.LLM_API_KEY || "";
  const LLM_BASE_URL = process.env.LLM_BASE_URL || "";
  const LLM_MODEL = process.env.LLM_MODEL || "gpt-3.5-turbo";

  if (!LLM_API_KEY || !LLM_BASE_URL) {
    return NextResponse.json({
      error: "未配置 LLM_API_KEY 或 LLM_BASE_URL",
      LLM_BASE_URL,
      hasKey: Boolean(LLM_API_KEY),
    });
  }

  try {
    const response = await fetch(`${LLM_BASE_URL}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${LLM_API_KEY}`,
      },
      body: JSON.stringify({
        model: LLM_MODEL,
        messages: [{ role: "user", content: "测试：请回复'成功'" }],
        max_tokens: 50,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      return NextResponse.json({
        error: "API 返回错误",
        status: response.status,
        statusText: response.statusText,
        response: data,
        config: {
          LLM_BASE_URL,
          LLM_MODEL,
          url: `${LLM_BASE_URL}/chat/completions`,
        },
      });
    }

    return NextResponse.json({
      success: true,
      message: data.choices?.[0]?.message?.content,
      fullResponse: data,
      config: {
        LLM_BASE_URL,
        LLM_MODEL,
      },
    });
  } catch (error) {
    return NextResponse.json({
      error: "调用失败",
      message: String(error),
      config: {
        LLM_BASE_URL,
        LLM_MODEL,
      },
    });
  }
}
