
import { GoogleGenAI, Type } from "@google/genai";

if (!process.env.API_KEY) {
    // In a real app, you would want to handle this more gracefully.
    // For this example, we assume the API key is provided via environment variables.
    console.warn("API_KEY environment variable not set. Using a placeholder.");
    process.env.API_KEY = "YOUR_API_KEY_HERE";
}

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

const videoInfoSchema = {
  type: Type.OBJECT,
  properties: {
    title: {
      type: Type.STRING,
      description: "A creative and plausible title for the YouTube video. Should be catchy and relevant."
    },
    summary: {
      type: Type.STRING,
      description: "A short, engaging one-paragraph summary of what the video might be about. Keep it under 50 words."
    }
  },
  required: ['title', 'summary']
};

interface VideoInfo {
  title: string;
  summary: string;
}

export const fetchVideoInfo = async (url: string): Promise<VideoInfo> => {
  try {
    const prompt = `Based on this YouTube URL, what could the video plausibly be about? Generate a creative title and a short, engaging summary for it. URL: ${url}`;
    
    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: videoInfoSchema,
      },
    });

    const jsonText = response.text.trim();
    if (!jsonText) {
        throw new Error("API returned an empty response.");
    }

    const parsedResponse = JSON.parse(jsonText);
    
    if (parsedResponse && parsedResponse.title && parsedResponse.summary) {
      return parsedResponse;
    } else {
      throw new Error("Invalid JSON structure from API");
    }

  } catch (error) {
    console.error("Error fetching video info from Gemini API:", error);
    // Fallback in case of API error
    return {
        title: "AI Could Not Determine Title",
        summary: "There was an issue generating the video summary. Please check the URL or try again later."
    };
  }
};
