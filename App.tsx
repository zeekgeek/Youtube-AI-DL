
import React, { useState } from 'react';
import { YoutubeIcon, SparklesIcon, LoaderIcon } from './components/icons';
import { fetchVideoInfo } from './services/geminiService';
import type { VideoDetails } from './types';

const VideoDetailCard: React.FC<{ details: VideoDetails, isDownloading: boolean, downloadProgress: number | null }> = ({ details, isDownloading, downloadProgress }) => {
  return (
    <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-2xl p-6 w-full max-w-2xl mx-auto shadow-lg animate-fade-in">
      <div className="flex flex-col md:flex-row gap-6">
        <img src={details.thumbnailUrl} alt="Video Thumbnail" className="w-full md:w-48 h-auto object-cover rounded-lg shadow-md" />
        <div className="flex-1">
          <h2 className="text-xl font-bold text-white mb-2">{details.title}</h2>
          <div className="flex items-center text-sm text-gray-400 mb-4">
            <SparklesIcon className="w-4 h-4 mr-2 text-purple-400" />
            <span>AI-Generated Title & Summary</span>
          </div>
          <p className="text-gray-300 text-sm leading-relaxed">{details.summary}</p>
        </div>
      </div>
      {isDownloading && downloadProgress !== null && (
        <div className="mt-4">
            <div className="w-full bg-gray-700 rounded-full h-2.5">
                <div 
                    className="bg-purple-600 h-2.5 rounded-full transition-width duration-150" 
                    style={{ width: `${downloadProgress}%` }}
                ></div>
            </div>
            <p className="text-center text-sm text-gray-300 mt-2">{downloadProgress.toFixed(0)}% downloaded</p>
        </div>
      )}
    </div>
  );
};


export default function App() {
  const [videoUrl, setVideoUrl] = useState('');
  const [videoDetails, setVideoDetails] = useState<VideoDetails | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);
  const [downloadProgress, setDownloadProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const extractVideoId = (url: string): string | null => {
    const regex = /(?:https?:\/\/)?(?:www\.)?(?:youtube\.com\/(?:[^\/\n\s]+\/\S+\/|(?:v|e(?:mbed)?)\/|\S*?[?&]v=)|youtu\.be\/)([a-zA-Z0-9_-]{11})/;
    const match = url.match(regex);
    return match ? match[1] : null;
  };

  const downloadFileWithProgress = async (url: string, filename: string) => {
    setIsDownloading(true);
    setDownloadProgress(0);
    console.log(`Starting download from: ${url}`);
    
    try {
      const response = await fetch(url);
      
      console.log('Fetch response status:', response.status);
      console.log('Fetch response headers:', Object.fromEntries(response.headers.entries()));
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      if (!response.body) {
        throw new Error('Response body is null.');
      }

      const contentLength = response.headers.get('content-length');
      if (!contentLength) {
        throw new Error('Content-Length response header unavailable.');
      }

      const total = parseInt(contentLength, 10);
      console.log(`Expected content length: ${total} bytes`);

      let receivedLength = 0;
      const chunks: Uint8Array[] = [];
      const reader = response.body.getReader();

      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        chunks.push(value);
        receivedLength += value.length;
        const progress = (receivedLength / total) * 100;
        setDownloadProgress(progress);
      }
      
      console.log(`Download complete. Total bytes received: ${receivedLength}`);
      if (receivedLength !== total) {
          console.warn(`Warning: Received bytes (${receivedLength}) does not match Content-Length (${total}).`);
      }

      const blob = new Blob(chunks, { type: 'video/mp4' });
      console.log(`Blob created with size: ${blob.size} bytes`);
      
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      const safeFilename = filename.replace(/[^a-z0-9_ -]/ig, '').trim() || 'video';
      link.download = `${safeFilename}.mp4`;
      
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(link.href);

    } catch (e) {
        console.error('Download failed:', e);
        const errorMessage = e instanceof Error ? e.message : 'An unknown download error occurred.';
        throw new Error(`Could not download the video file. ${errorMessage}`);
    } finally {
        setIsDownloading(false);
        setDownloadProgress(null);
    }
  };


  const handleFetchVideo = async () => {
    if (!videoUrl) {
      setError('Please enter a YouTube URL.');
      return;
    }
    const videoId = extractVideoId(videoUrl);
    if (!videoId) {
      setError('Invalid YouTube URL. Please check and try again.');
      return;
    }
    
    setIsLoading(true);
    setError(null);
    setVideoDetails(null);

    try {
      // Step 1: Fetch AI-generated info first to get a title for the filename
      const info = await fetchVideoInfo(videoUrl);
      const thumbnailUrl = `https://img.youtube.com/vi/${videoId}/hqdefault.jpg`;
      const details: VideoDetails = {
        id: videoId,
        title: info.title,
        summary: info.summary,
        thumbnailUrl: thumbnailUrl,
      };
      setVideoDetails(details);
      
      // Step 2: Trigger the download using the fetched title.
      // NOTE: Direct YouTube download is not feasible. This uses a large sample video 
      // to demonstrate a real streaming download with progress tracking.
      await downloadFileWithProgress(
        'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4', 
        details.title
      );
      
    } catch (err) {
      const errorMessage = (err instanceof Error) ? err.message : 'An unknown error occurred.';
      setError(`Failed to process video. ${errorMessage}`);
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };
  

  return (
    <div className="min-h-screen bg-gray-900 text-white font-sans flex flex-col items-center justify-center p-4 relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-gray-900 via-purple-900/40 to-gray-900"></div>
      <div className="absolute top-0 left-0 w-full h-full bg-[url('data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20viewBox%3D%220%200%20800%20800%22%3E%3Cdefs%3E%3Cfilter%20id%3D%22a%22%20x%3D%22-20%25%22%20y%3D%22-20%25%22%20width%3D%22140%25%22%20height%3D%22140%25%22%20filterUnits%3D%22objectBoundingBox%22%20primitiveUnits%3D%22userSpaceOnUse%22%20color-interpolation-filters%3D%22sRGB%22%3E%3CfeTurbulence%20type%3D%22fractalNoise%22%20baseFrequency%3D%22.55%22%20numOctaves%3D%224%22%20stitchTiles%3D%22stitch%22%20x%3D%220%25%22%20y%3D%220%25%22%20width%3D%22100%25%22%20height%3D%22100%25%22%20result%3D%22noise%22/%3E%3CfeDiffuseLighting%20in%3D%22noise%22%20lighting-color%3D%22%236d28d9%22%20surfaceScale%3D%222%22%20x%3D%220%25%22%20y%3D%220%25%22%20width%3D%22100%25%22%20height%3D%22100%25%22%20result%3D%22litNoise%22%3E%3CfeDistantLight%20azimuth%3D%22-135%22%20elevation%3D%2235%22/%3E%3C/feDiffuseLighting%3E%3CfeComposite%20in%3D%22litNoise%22%20in2%3D%22SourceAlpha%22%20operator%3D%22in%22%20x%3D%3D%220%25%22%20y%3D%220%25%22%20width%3D%22100%25%22%20height%3D%22100%25%22%20result%3D%22litNoise%22/%3E%3CfeBlend%20in%3D%22SourceGraphic%22%20in2%3D%22litNoise%22%20mode%3D%22multiply%22%20x%3D%220%25%22%20y%3D%220%25%22%20width%3D%22100%25%22%20height%3D%22100%25%22%20result%3D%22blend%22/%3E%3C/filter%3E%3C/defs%3E%3Crect%20width%3D%22800%22%20height%3D%22800%22%20fill%3D%22%23000000%22/%3E%3Crect%20width%3D%22800%22%20height%3D%22800%22%20fill%3D%22%230f0f21%22%20filter%3D%22url(%23a)%22%20opacity%3D%220.3%22/%3E%3C/svg%3E')] opacity-20"></div>
      
      <main className="z-10 w-full max-w-2xl px-4 flex flex-col gap-8 items-center">
        <div className="text-center">
          <h1 className="text-4xl md:text-5xl font-extrabold text-white tracking-tight">
            AI Video Saver
          </h1>
          <p className="mt-4 text-lg text-gray-300">
            Paste a YouTube link to get an AI-generated summary and download the video.
          </p>
        </div>

        <div className="w-full">
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
              <YoutubeIcon className="w-6 h-6 text-gray-400" />
            </div>
            <input
              type="text"
              value={videoUrl}
              onChange={(e) => setVideoUrl(e.target.value)}
              placeholder="https://www.youtube.com/watch?v=..."
              className="w-full bg-gray-800/80 border border-gray-700 text-white placeholder-gray-500 rounded-lg py-3 pl-12 pr-4 focus:ring-2 focus:ring-purple-500 focus:border-purple-500 outline-none transition-all duration-300"
              disabled={isLoading || isDownloading}
            />
          </div>
          <button
            onClick={handleFetchVideo}
            disabled={isLoading || isDownloading}
            className="mt-4 w-full bg-purple-600 hover:bg-purple-700 text-white font-bold py-3 px-4 rounded-lg transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {isLoading ? (
              <>
                <LoaderIcon className="w-5 h-5 animate-spin" />
                Fetching Info...
              </>
            ) : isDownloading ? (
                <>
                <LoaderIcon className="w-5 h-5 animate-spin" />
                Downloading...
              </>
            ) : (
              'Fetch Video'
            )}
          </button>
        </div>
        
        {error && <p className="text-red-400 bg-red-900/50 p-3 rounded-lg">{error}</p>}
        
        {videoDetails && (
          <VideoDetailCard 
            details={videoDetails}
            isDownloading={isDownloading}
            downloadProgress={downloadProgress}
          />
        )}
      </main>

      <footer className="z-10 text-center text-gray-500 text-sm mt-12">
        <p>Built with React, Tailwind CSS, and the Gemini API.</p>
      </footer>
    </div>
  );
}
