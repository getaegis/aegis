/**
 * useWebSocket — persistent connection for real-time request feed
 *
 * Uses reconnecting-websocket for reliable auto-reconnect with backoff.
 * Not React Query — WebSocket is a persistent stream, not request/response.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import ReconnectingWebSocket from 'reconnecting-websocket';
import type { AuditEntry } from '../types';

export type ConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'reconnecting';

interface UseWebSocketOptions {
  /** Called for each new request that comes through Gate */
  onMessage?: (entry: AuditEntry) => void;
  /** Enable/disable the connection (e.g., only when on RequestFeed view) */
  enabled?: boolean;
}

interface UseWebSocketResult {
  status: ConnectionStatus;
  /** Manually reconnect */
  reconnect: () => void;
}

const WS_URL = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`;

export function useWebSocket(options: UseWebSocketOptions = {}): UseWebSocketResult {
  const { onMessage, enabled = true } = options;
  const [status, setStatus] = useState<ConnectionStatus>('connecting');
  const wsRef = useRef<ReconnectingWebSocket | null>(null);
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  useEffect(() => {
    if (!enabled) {
      setStatus('disconnected');
      return;
    }

    const ws = new ReconnectingWebSocket(WS_URL, [], {
      maxReconnectionDelay: 15000,
      minReconnectionDelay: 1000,
      reconnectionDelayGrowFactor: 2,
      maxRetries: 10,
    });
    wsRef.current = ws;
    let wasConnected = false;

    ws.addEventListener('open', () => {
      wasConnected = true;
      setStatus('connected');
    });

    ws.addEventListener('close', () => {
      // reconnecting-websocket fires close on every failed attempt AND when
      // retries are exhausted. We show 'reconnecting' during attempts and
      // only transition to 'disconnected' after the library gives up.
      // The library sets readyState to CLOSED (3) when it stops retrying.
      if (ws.readyState === WebSocket.CLOSED) {
        setStatus('disconnected');
      } else if (wasConnected) {
        setStatus('reconnecting');
      } else {
        // Never connected yet — still in initial connection attempts
        setStatus('reconnecting');
      }
    });

    ws.addEventListener('message', (event: MessageEvent) => {
      try {
        const entry = JSON.parse(event.data as string) as AuditEntry;
        onMessageRef.current?.(entry);
      } catch {
        // Ignore malformed messages
      }
    });

    return () => {
      ws.close();
      wsRef.current = null;
      setStatus('disconnected');
    };
  }, [enabled]);

  const reconnect = useCallback(() => {
    wsRef.current?.reconnect();
  }, []);

  return { status, reconnect };
}
