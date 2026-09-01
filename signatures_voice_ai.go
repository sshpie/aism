package main

// signatures_voice_ai.go extends the signatures table with fingerprints for
// voice AI platforms: TTS (text-to-speech), ASR (automatic speech recognition),
// and voice infrastructure services.
//
// Data sources:
//   - voice-ai-snake DETECT_CHECKS (engine.py) — authoritative for checked platforms
//   - galleria corpus (339 AI/ML platforms) — port sets
//   - VDT intel corpus (~/VDT/intel/voice-ai/voice-ai-wiki.md) — 59-platform table
//
// Confirm paths are sourced from snake's tested probes; for Gradio-based platforms
// Gradio's /info endpoint exposes a JSON {"title":"<AppName>"} that uniquely
// identifies each app. WebSocket-primary services (Vosk 2700, FunASR 10095) are
// included for port-coverage only with rootHint-based detection.
//
// Families introduced:
//   voice-synthesis    — TTS and voice cloning services
//   voice-asr          — ASR/STT services
//   voice-infrastructure — voice assistant platforms, VAD, monitoring

var voiceAISignatures = []llmSignature{

	// ── Text-to-Speech / Voice Synthesis ─────────────────────────────────

	// OpenAI-compatible voice API; voice IDs begin with "af_", "bm_", etc.
	{platform: "Kokoro TTS", family: "voice-synthesis", ports: []int{8880, 8000, 8001},
		confirmPath: "/v1/audio/voices", confirmHint: `"af_"`,
		noAuth: true},

	// REST API; /api/ready returns ready status JSON
	{platform: "AllTalk TTS", family: "voice-synthesis", ports: []int{7851, 7852, 7500},
		confirmPath: "/api/ready", confirmHint: `"status"`,
		noAuth: true},

	// /model_info returns model metadata embedding the CosyVoice name
	{platform: "CosyVoice 2", family: "voice-synthesis", ports: []int{50000, 9880, 8000, 8012},
		confirmPath: "/model_info", confirmHint: `CosyVoice`,
		noAuth: true},

	// REST API; /details returns version dict mentioning "Coqui" brand
	{platform: "Coqui TTS", family: "voice-synthesis", ports: []int{5002},
		confirmPath: "/details", confirmHint: `"Coqui"`,
		noAuth: true},

	// FastAPI TTS server; /openapi.json title = "Fish Speech"
	{platform: "Fish Speech", family: "voice-synthesis", ports: []int{8080, 8000, 7860},
		confirmPath: "/openapi.json", confirmHint: `Fish Speech`,
		noAuth: true},

	// FastAPI voice-clone + TTS; /docs page title contains GPT-SoVITS
	{platform: "GPT-SoVITS", family: "voice-synthesis", ports: []int{9880, 9874, 9872, 9873},
		confirmPath: "/docs", confirmHint: `GPT-SoVITS`,
		noAuth: true},

	// Multi-lingual TTS; Gradio /info title = "MeloTTS"
	{platform: "MeloTTS", family: "voice-synthesis", ports: []int{8888, 8000},
		rootHint:    "MeloTTS",
		confirmPath: "/info", confirmHint: `"MeloTTS"`,
		noAuth: true},

	// Multi-engine TTS gateway; /api/voices returns keyed voice dict
	{platform: "OpenTTS", family: "voice-synthesis", ports: []int{5500},
		confirmPath: "/api/voices", confirmHint: `"voice"`,
		noAuth: true},

	// Java linguistic TTS platform; /api returns voice listing HTML
	{platform: "MaryTTS", family: "voice-synthesis", ports: []int{59125},
		confirmPath: "/api", confirmHint: `Mary`,
		noAuth: true},

	// Gradio zero-shot TTS; /info JSON title = "F5 TTS"
	{platform: "F5-TTS", family: "voice-synthesis", ports: []int{7860},
		rootHint:    "F5",
		confirmPath: "/info", confirmHint: `"F5 TTS"`,
		noAuth: true},

	// Suno Bark Gradio interface; /info JSON title contains "Bark"
	{platform: "Bark TTS", family: "voice-synthesis", ports: []int{7860, 5000},
		rootHint:    "Bark",
		confirmPath: "/info", confirmHint: `"Bark"`,
		noAuth: true},

	// Gradio neural TTS; /info JSON title = "StyleTTS"
	{platform: "StyleTTS2", family: "voice-synthesis", ports: []int{7860, 8000, 4321},
		rootHint:    "StyleTTS",
		confirmPath: "/info", confirmHint: `"StyleTTS"`,
		noAuth: true},

	// MyShell voice cloning; Gradio /info title = "OpenVoice"
	{platform: "OpenVoice", family: "voice-synthesis", ports: []int{7860},
		rootHint:    "OpenVoice",
		confirmPath: "/info", confirmHint: `"OpenVoice"`,
		noAuth: true},

	// Smart speaker OS REST API; /api/v1/info returns type = "OpenVoiceOS"
	{platform: "OpenVoiceOS", family: "voice-synthesis", ports: []int{8181, 18181},
		confirmPath: "/api/v1/info", confirmHint: `OpenVoiceOS`,
		noAuth: true},

	// FastAPI TTS server; /openapi.json title contains "Orpheus"
	{platform: "Orpheus TTS", family: "voice-synthesis", ports: []int{5005, 8080},
		confirmPath: "/openapi.json", confirmHint: `Orpheus`,
		noAuth: true},

	// OpenAI-compatible TTS gateway; /v1/models returns TTS-specific models
	{platform: "OpenedAI Speech", family: "voice-synthesis", ports: []int{8000, 8080},
		confirmPath: "/v1/models", confirmHint: `"tts-1"`,
		noAuth: true},

	// Voice conversion (RVC); Gradio at port 7865, /info title = "Retrieval"
	{platform: "RVC WebUI", family: "voice-synthesis", ports: []int{7865},
		confirmPath: "/info", confirmHint: `"Retrieval"`,
		noAuth: true},

	// Emotional TTS; FastAPI /openapi.json title = "EmotiVoice"
	{platform: "EmotiVoice", family: "voice-synthesis", ports: []int{8000, 8501},
		confirmPath: "/openapi.json", confirmHint: `EmotiVoice`,
		noAuth: true},

	// FastAPI TTS; /openapi.json title = "Chatterbox"
	{platform: "Chatterbox TTS", family: "voice-synthesis", ports: []int{8000, 7860},
		rootHint:    "Chatterbox",
		confirmPath: "/openapi.json", confirmHint: `Chatterbox`,
		noAuth: true},

	// Gradio or FastAPI TTS; /info title = "ChatTTS"
	{platform: "ChatTTS", family: "voice-synthesis", ports: []int{8080, 7860},
		rootHint:    "ChatTTS",
		confirmPath: "/info", confirmHint: `"ChatTTS"`,
		noAuth: true},

	// FastAPI TTS; distinctive port 58003, /openapi.json title = "MetaVoice"
	{platform: "MetaVoice", family: "voice-synthesis", ports: []int{58003, 7861},
		confirmPath: "/openapi.json", confirmHint: `MetaVoice`,
		noAuth: true},

	// Industrial-grade TTS; Gradio /info title = "IndexTTS"
	{platform: "IndexTTS", family: "voice-synthesis", ports: []int{7860},
		rootHint:    "IndexTTS",
		confirmPath: "/info", confirmHint: `"IndexTTS"`,
		noAuth: true},

	// Neural TTS; Gradio /info title = "MegaTTS"
	{platform: "MegaTTS3", family: "voice-synthesis", ports: []int{7860},
		rootHint:    "MegaTTS",
		confirmPath: "/info", confirmHint: `"MegaTTS"`,
		noAuth: true},

	// Spark-TTS streaming; Gradio /info title = "Spark TTS"
	{platform: "Spark TTS", family: "voice-synthesis", ports: []int{7860, 8000, 8001, 8002},
		rootHint:    "Spark",
		confirmPath: "/info", confirmHint: `"Spark TTS"`,
		noAuth: true},

	// High-quality generative TTS; Gradio /info title = "Parler"
	{platform: "Parler TTS", family: "voice-synthesis", ports: []int{7860},
		rootHint:    "Parler",
		confirmPath: "/info", confirmHint: `"Parler"`,
		noAuth: true},

	// High-quality slow TTS; Gradio /info title = "Tortoise"
	{platform: "Tortoise TTS", family: "voice-synthesis", ports: []int{7860, 5000},
		rootHint:    "Tortoise",
		confirmPath: "/info", confirmHint: `"Tortoise"`,
		noAuth: true},

	// Real-time voice LLM; web UI at 8998 contains "moshi" branding
	{platform: "Moshi", family: "voice-synthesis", ports: []int{8998, 8088, 8008},
		rootHint:    "moshi",
		confirmPath: "/", confirmHint: `moshi`,
		noAuth: true},

	// Advanced voice-clone GUI; distinctive port 6969
	{platform: "Applio", family: "voice-synthesis", ports: []int{6969},
		rootHint:    "Applio",
		confirmPath: "/", confirmHint: `Applio`,
		noAuth: true},

	// Lightweight neural TTS HTTP server; /api/v1/info → piper
	{platform: "Piper TTS", family: "voice-synthesis", ports: []int{10200, 5000},
		confirmPath: "/api/v1/info", confirmHint: `piper`,
		noAuth: true},

	// ── Automatic Speech Recognition (ASR/STT) ───────────────────────────

	// Whisper with speaker diarization; root page contains "WhisperX" branding
	{platform: "WhisperX", family: "voice-asr", ports: []int{8000, 8080, 9000},
		confirmPath: "/", confirmHint: `WhisperX`,
		noAuth: true},

	// Popular Docker ASR image; FastAPI at 9000, /openapi.json title
	{platform: "Whisper ASR Webservice", family: "voice-asr", ports: []int{9000},
		confirmPath: "/openapi.json", confirmHint: `Speech to text`,
		noAuth: true},

	// Whisper with diarization; /openapi.json contains "diarize" schema key
	{platform: "Modern Whisper", family: "voice-asr", ports: []int{8000, 8080},
		rootHint:    "Modern Whisper",
		confirmPath: "/openapi.json", confirmHint: `diarize`,
		noAuth: true},

	// Subtitle generation via WhisperX; /api/v1/models returns whisperx model info
	{platform: "Subtitle Generator", family: "voice-asr", ports: []int{8000, 8080},
		confirmPath: "/api/v1/models", confirmHint: `whisperx`,
		noAuth: true},

	// Real-time Whisper; WebSocket primary at 9090, HTTP /status endpoint
	{platform: "WhisperLive", family: "voice-asr", ports: []int{9090},
		confirmPath: "/status", confirmHint: `transcription`,
		noAuth: true},

	// Whisper.cpp HTTP server; lightweight C++, root page contains "Whisper"
	{platform: "Whisper.cpp Server", family: "voice-asr", ports: []int{8080},
		rootHint:    "whisper",
		confirmPath: "/", confirmHint: `Whisper`,
		noAuth: true},

	// Alibaba ASR; HTTP at 10096, WebSocket at 10095 (WS-primary, HTTP fallback)
	{platform: "FunASR", family: "voice-asr", ports: []int{10096, 10095, 8000},
		confirmPath: "/", confirmHint: `funasr`,
		noAuth: true},

	// E2E speech recognition REST API; /api/v1/asr nbest field in response
	{platform: "WeNet", family: "voice-asr", ports: []int{10086},
		confirmPath: "/", confirmHint: `wenet`,
		noAuth: true},

	// GPU real-time Whisper; root page contains "WhisperFusion"
	{platform: "WhisperFusion", family: "voice-asr", ports: []int{8000, 6006},
		rootHint:    "WhisperFusion",
		confirmPath: "/", confirmHint: `WhisperFusion`,
		noAuth: true},

	// Offline STT; WebSocket-only at 2700, root returns vosk server info
	{platform: "Vosk", family: "voice-asr", ports: []int{2700},
		rootHint: "vosk",
		noAuth:   true},

	// ── Voice Infrastructure ─────────────────────────────────────────────

	// Offline voice assistant; REST API /api/profile returns rhasspy keys
	{platform: "Rhasspy", family: "voice-infrastructure", ports: []int{12101},
		confirmPath: "/api/profile", confirmHint: `"rhasspy"`,
		noAuth: true},

	// Voice activity detection REST service; /health returns silero marker
	{platform: "Silero VAD", family: "voice-infrastructure", ports: []int{8000, 5000, 10400},
		confirmPath: "/health", confirmHint: `silero`,
		noAuth: true},

	// LLM/voice observability; /api/v1/health contains "lunary" key
	{platform: "Lunary", family: "voice-infrastructure", ports: []int{3000, 8000},
		confirmPath: "/api/v1/health", confirmHint: `lunary`,
		noAuth: true},
}

func init() {
	// Slot voice AI fingerprints before the generic OpenAI-compatible catch-all
	// (the last entry in signatures). Same priority logic as signatures_tome.go.
	if len(signatures) == 0 {
		signatures = voiceAISignatures
		return
	}
	last := signatures[len(signatures)-1]
	signatures = append(signatures[:len(signatures)-1], voiceAISignatures...)
	signatures = append(signatures, last)
}
