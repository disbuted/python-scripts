import yt_dlp
import os

url = input("Enter the YouTube video URL: ")

# yt-dlp options for downloading audio
ydl_opts = {
    'format': 'bestaudio/best',  # Download the best audio format
    'outtmpl': './Audio/Audio.mp3',  # Save it as 'Audio.mp3' in './Audio' folder
    'noplaylist': True,  # Ensure it does not download a playlist
}

# Ensure the output folder exists
output_path = './Audio'
if not os.path.exists(output_path):
    os.makedirs(output_path)

# Download the audio using yt-dlp
with yt_dlp.YoutubeDL(ydl_opts) as ydl:
    try:
        ydl.download([url])
        print(f"Audio downloaded successfully to {output_path}/Audio.mp3")
    except Exception as e:
        print(f"An error occurred: {e}")
