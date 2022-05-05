from azure.cognitiveservices.speech import AudioDataStream, SpeechConfig, SpeechSynthesizer
from azure.cognitiveservices.speech.audio import AudioOutputConfig

speech_key = "e561062262c04219b9e48ae51070c37b"
service_region = "eastus"
speech_config = SpeechConfig(subscription=speech_key, region=service_region)

speech_config.speech_synthesis_language = "en-US"
speech_config.speech_synthesis_voice_name ="en-US-BrandonNeural"

audio_config = AudioOutputConfig(filename="reflex.wav")
synthesizer = SpeechSynthesizer(speech_config=speech_config, audio_config=audio_config)


with open('text.txt', 'r',encoding='utf-8',errors='ignore') as f:
    text = f.read()
result = synthesizer.speak_text_async(text).get()
stream = AudioDataStream(result)
stream.save_to_wav_file("reflex.wav")

