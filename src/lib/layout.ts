/** Bubbles sit in the corners around the orb when the stage is wide enough; otherwise they go in a grid below it. */
export function orbLayout(stageWidth: number): { compact: boolean; orbSize: number } {
  if (stageWidth >= 420) return { compact: false, orbSize: Math.max(260, Math.min(350, stageWidth - 130)) };
  return { compact: true, orbSize: Math.max(220, Math.min(300, stageWidth - 40)) };
}
