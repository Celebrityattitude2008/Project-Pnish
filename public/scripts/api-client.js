export async function fetchUrlIntelligence(url) {
  try {
    const response = await fetch(`/api/intelligence?url=${encodeURIComponent(url)}`);
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || 'Failed to fetch intelligence');
    }
    return await response.json();
  } catch (error) {
    return { error: error.message };
  }
}

export function getScreenshotUrl(url) {
  return `https://image.thum.io/get/${encodeURIComponent(url)}`;
}
