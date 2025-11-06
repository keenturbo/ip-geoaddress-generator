import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'edge';

export async function GET(request: NextRequest) {
  try {
    // 记录所有可能包含 IP 的请求头
    const headers = {
      'cf-connecting-ip': request.headers.get('cf-connecting-ip'),
      'x-real-ip': request.headers.get('x-real-ip'),
      'x-forwarded-for': request.headers.get('x-forwarded-for'),
      'x-client-ip': request.headers.get('x-client-ip'),
    };

    console.log('IP API 被调用');
    console.log('请求头信息:', JSON.stringify(headers, null, 2));

    // 按优先级获取 IP
    const ip = 
      request.headers.get('cf-connecting-ip') || 
      request.headers.get('x-real-ip') || 
      request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
      request.headers.get('x-client-ip') ||
      'Unknown';

    console.log('解析出的 IP:', ip);

    // 返回详细信息用于调试
    return NextResponse.json({ 
      ip,
      debug: {
        headers,
        timestamp: new Date().toISOString(),
        runtime: 'edge'
      }
    });
  } catch (error) {
    console.error('IP API 错误:', error);
    return NextResponse.json(
      { 
        error: 'Failed to get IP',
        message: error instanceof Error ? error.message : 'Unknown error',
        ip: 'Error'
      },
      { status: 500 }
    );
  }
}