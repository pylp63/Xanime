export interface XAnime {
  id: number; title: string; cover: string; description: string;
  category: string; episodes: number; year: number; rating: number;
  created_at?: string;
}

export interface Episode {
  id: number; xanime_id: number; number: number;
  title: string; video_url: string; duration: number;
}

export function getCoverUrl(cover: string): string {
  if (!cover || cover.trim() === "") {
    return "https://via.placeholder.com/480x640/111113/eeeeee?text=Xanime";
  }
  if (cover.startsWith("http")) return cover;
  if (cover.startsWith("/")) return cover;
  return `/static/${cover}`;
}