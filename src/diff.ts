/**
 * Simple diff utility for showing before/after changes
 */

export interface DiffLine {
  type: 'add' | 'remove' | 'unchanged';
  content: string;
  lineNumber?: number;
}

/**
 * Generate a simple line-based diff between two strings
 */
export function diffLines(oldStr: string, newStr: string): DiffLine[] {
  const oldLines = oldStr.split('\n');
  const newLines = newStr.split('\n');
  const result: DiffLine[] = [];

  // Simple LCS-based diff (for short strings)
  // For longer strings, just show removed then added
  if (oldLines.length + newLines.length > 100) {
    // Simple approach for long diffs
    for (const line of oldLines) {
      result.push({ type: 'remove', content: line });
    }
    for (const line of newLines) {
      result.push({ type: 'add', content: line });
    }
    return result;
  }

  // Compute LCS for smaller diffs
  const lcs = computeLCS(oldLines, newLines);
  let oldIdx = 0;
  let newIdx = 0;

  for (const common of lcs) {
    // Lines removed from old
    while (oldIdx < common.oldIdx) {
      const line = oldLines[oldIdx];
      result.push({ type: 'remove', content: line ?? '', lineNumber: oldIdx + 1 });
      oldIdx++;
    }
    // Lines added in new
    while (newIdx < common.newIdx) {
      const line = newLines[newIdx];
      result.push({ type: 'add', content: line ?? '', lineNumber: newIdx + 1 });
      newIdx++;
    }
    // Common line
    const commonLine = oldLines[oldIdx];
    result.push({ type: 'unchanged', content: commonLine ?? '', lineNumber: newIdx + 1 });
    oldIdx++;
    newIdx++;
  }

  // Remaining lines
  while (oldIdx < oldLines.length) {
    const line = oldLines[oldIdx];
    result.push({ type: 'remove', content: line ?? '', lineNumber: oldIdx + 1 });
    oldIdx++;
  }
  while (newIdx < newLines.length) {
    const line = newLines[newIdx];
    result.push({ type: 'add', content: line ?? '', lineNumber: newIdx + 1 });
    newIdx++;
  }

  return result;
}

interface LCSMatch {
  oldIdx: number;
  newIdx: number;
}

function computeLCS(oldLines: string[], newLines: string[]): LCSMatch[] {
  const m = oldLines.length;
  const n = newLines.length;

  // DP table
  const dp: number[][] = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const oldLine = oldLines[i - 1];
      const newLine = newLines[j - 1];
      const prevDiag = dp[i - 1]?.[j - 1] ?? 0;
      const prevUp = dp[i - 1]?.[j] ?? 0;
      const prevLeft = dp[i]?.[j - 1] ?? 0;

      const row = dp[i];
      if (row) {
        if (oldLine === newLine) {
          row[j] = prevDiag + 1;
        } else {
          row[j] = Math.max(prevUp, prevLeft);
        }
      }
    }
  }

  // Backtrack to find LCS
  const result: LCSMatch[] = [];
  let i = m;
  let j = n;

  while (i > 0 && j > 0) {
    const oldLine = oldLines[i - 1];
    const newLine = newLines[j - 1];
    const prevUp = dp[i - 1]?.[j] ?? 0;
    const prevLeft = dp[i]?.[j - 1] ?? 0;

    if (oldLine === newLine) {
      result.unshift({ oldIdx: i - 1, newIdx: j - 1 });
      i--;
      j--;
    } else if (prevUp > prevLeft) {
      i--;
    } else {
      j--;
    }
  }

  return result;
}
