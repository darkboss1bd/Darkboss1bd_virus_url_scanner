import tkinter as tk
from tkinter import messagebox
import requests
import threading
import time
import json

# Hacker animation simulator
def loading_animation(label):
    chars = "⢿⣻⣽⣾⣷⣯⣟⡿"
    i = 0
    while getattr(loading_animation, "running", True):
        label.config(text=chars[i % len(chars)] + " Scanning with VirusTotal...")
        time.sleep(0.1)
        i += 1

# Real VirusTotal API check function
def real_virus_check(url):
    try:
        # Replace with your actual VirusTotal API key
        api_key = "f1a36bf732b159ef1136d1b099c24bbfebb2eca6177c3e42661c4fd97c32539e"
        scan_url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': api_key, 'resource': url}
        
        response = requests.get(scan_url, params=params, timeout=30)
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"API Error: {response.status_code}"}
    except Exception as e:
        return {"error": f"Connection Error: {str(e)}"}

# URL checking function with real API
def check_url():
    url = url_entry.get().strip()
    if not url:
        messagebox.showerror("Error", "Please enter a URL!")
        return
        
    if not url.startswith("http"):
        url = "http://" + url

    # Start animation
    loading_animation.running = True
    anim_thread = threading.Thread(target=loading_animation, args=(loading_label,))
    anim_thread.daemon = True
    anim_thread.start()

    # Real URL check with VirusTotal API
    def scan_url():
        try:
            result = real_virus_check(url)
            loading_animation.running = False

            result_text.config(state="normal")
            result_text.delete(1.0, tk.END)

            if "error" in result:
                result_text.insert(tk.END, f"[❌ ERROR] {result['error']}\n", "error")
                result_text.insert(tk.END, "Please check your API key and internet connection.\n", "info")
            elif "response_code" in result:
                if result["response_code"] == 1:  # URL found in database
                    positives = result["positives"]
                    total = result["total"]
                    
                    if positives > 0:
                        result_text.insert(tk.END, f"[⚠️ MALWARE DETECTED] {url}\n", "danger")
                        result_text.insert(tk.END, f"⚠️ THREAT LEVEL: {positives}/{total} antivirus engines flagged this URL\n", "danger")
                        result_text.insert(tk.END, f"📊 Scan Date: {result.get('scan_date', 'N/A')}\n", "info")
                        
                        # Show which engines detected it
                        result_text.insert(tk.END, "\n🛡️ DETECTION DETAILS:\n", "info")
                        for engine, detection in result["scans"].items():
                            if detection["detected"]:
                                result_text.insert(tk.END, f"  • {engine}: {detection['result']}\n", "danger")
                    else:
                        result_text.insert(tk.END, f"[✅ SAFE] {url}\n", "safe")
                        result_text.insert(tk.END, f"✅ This URL is clean. Scanned by {total} antivirus engines.\n", "safe")
                else:
                    result_text.insert(tk.END, f"[❓ UNKNOWN] {url}\n", "info")
                    result_text.insert(tk.END, "This URL is not in VirusTotal database. Be cautious!\n", "info")
            else:
                result_text.insert(tk.END, f"[❌ API ERROR] Invalid response from VirusTotal\n", "error")
                
        except Exception as e:
            loading_animation.running = False
            result_text.config(state="normal")
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"[❌ ERROR] {str(e)}\n", "error")
            
        result_text.config(state="disabled")

    threading.Thread(target=scan_url).start()

# Clear function
def clear_all():
    url_entry.delete(0, tk.END)
    result_text.config(state="normal")
    result_text.delete(1.0, tk.END)
    result_text.config(state="disabled")
    loading_label.config(text="")

# About function
def show_about():
    about_text = """VIRUS URL CHECKER v2.0
Real-time Malware Detection using VirusTotal API

Features:
• Real antivirus scanning with 70+ engines
• Professional cyber security interface
• Hacker-style animations and design
• Detailed threat analysis reports

Instructions:
1. Get free API key from virustotal.com
2. Replace YOUR_VIRUSTOTAL_API_KEY_HERE in code
3. Enter any URL to scan for malware
4. Get instant security results

Built with Python, Tkinter & VirusTotal API"""
    messagebox.showinfo("About Virus URL Checker", about_text)

# API Setup Instructions
def show_api_instructions():
    instructions = """🔧 VIRUS TOTAL API SETUP INSTRUCTIONS:

1. Visit: https://www.virustotal.com/
2. Sign up for a FREE account
3. Go to your profile → API Key
4. Copy your API key
5. Replace 'YOUR_VIRUSTOTAL_API_KEY_HERE' 
   in the code with your actual key
6. Save and restart the program

⚠️ Free API Limit: 4 requests/minute
⚠️ For heavy usage, consider premium API

Your current status: API KEY NOT SET"""
    messagebox.showinfo("API Setup Instructions", instructions)

# Create GUI
root = tk.Tk()
root.title("💀 DARKBOSS1BD-HACKER CYBER SECURITY - VIRUS TOTAL URL SCANNER 💀")
root.geometry("800x600")
root.configure(bg="#0d0d0d")
root.resizable(True, True)

# Banner
banner = tk.Label(root, text="💀 CYBER SECURITY HACKER MALWARE DETECTOR 💀", 
                  font=("Courier", 18, "bold"), fg="#00ff00", bg="#0d0d0d")
banner.pack(pady=15)

subtitle = tk.Label(root, text=" darkboss1bd Advanced URL Scanner with VirusTotal API Integration", 
                   font=("Courier", 11), fg="#00cc00", bg="#0d0d0d")
subtitle.pack(pady=5)

# URL Input Section
url_frame = tk.Frame(root, bg="#0d0d0d")
url_frame.pack(pady=15)

url_label = tk.Label(url_frame, text="Enter Website URL to Scan:", 
                    font=("Courier", 12), fg="white", bg="#0d0d0d")
url_label.pack(pady=5)

url_entry = tk.Entry(url_frame, width=70, font=("Courier", 12), 
                    bg="#1a1a1a", fg="#00ff00", insertbackground="white")
url_entry.pack(pady=5)

# Button Frame
button_frame = tk.Frame(root, bg="#0d0d0d")
button_frame.pack(pady=15)

# Scan Button
check_button = tk.Button(button_frame, text="🔍 SCAN WITH VIRUSTOTAL", 
                        font=("Courier", 11, "bold"), 
                        bg="#003300", fg="#00ff00", 
                        activebackground="#006600",
                        activeforeground="#ffffff",
                        command=check_url,
                        padx=15, pady=8)
check_button.pack(side=tk.LEFT, padx=5)

# Clear Button
clear_button = tk.Button(button_frame, text="🗑️ CLEAR", 
                        font=("Courier", 11, "bold"), 
                        bg="#330000", fg="#ff0000", 
                        activebackground="#660000",
                        activeforeground="#ffffff",
                        command=clear_all,
                        padx=15, pady=8)
clear_button.pack(side=tk.LEFT, padx=5)

# About Button
about_button = tk.Button(button_frame, text="ℹ️ ABOUT", 
                        font=("Courier", 11, "bold"), 
                        bg="#000033", fg="#00ccff", 
                        activebackground="#000066",
                        activeforeground="#ffffff",
                        command=show_about,
                        padx=15, pady=8)
about_button.pack(side=tk.LEFT, padx=5)

# API Setup Button
api_button = tk.Button(button_frame, text="🔑 API SETUP", 
                      font=("Courier", 11, "bold"), 
                      bg="#333300", fg="#ffff00", 
                      activebackground="#666600",
                      activeforeground="#ffffff",
                      command=show_api_instructions,
                      padx=15, pady=8)
api_button.pack(side=tk.LEFT, padx=5)

# Loading Animation Label
loading_label = tk.Label(root, text="", font=("Courier", 12), fg="#00ff00", bg="#0d0d0d")
loading_label.pack(pady=8)

# Results Section
result_label = tk.Label(root, text="SCAN RESULTS & THREAT ANALYSIS:", 
                       font=("Courier", 13, "bold"), fg="#ffff00", bg="#0d0d0d")
result_label.pack(pady=8)

# Results Text Box
result_frame = tk.Frame(root, bg="#0d0d0d")
result_frame.pack(pady=15, padx=25, fill=tk.BOTH, expand=True)

result_text = tk.Text(result_frame, height=15, width=80, 
                     font=("Courier", 10), 
                     bg="#1a1a1a", fg="#00ff00", 
                     state="disabled",
                     wrap=tk.WORD)
result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Scrollbar
scrollbar = tk.Scrollbar(result_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
result_text.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=result_text.yview)

# Tag styles
result_text.tag_config("danger", foreground="red", font=("Courier", 10, "bold"))
result_text.tag_config("safe", foreground="green", font=("Courier", 10, "bold"))
result_text.tag_config("info", foreground="yellow")
result_text.tag_config("error", foreground="#ff6600", font=("Courier", 10, "bold"))

# Footer
footer = tk.Label(root, text="🛡️ PROTECT YOURSELF FROM CYBER THREATS - POWERED BY VIRUSTOTAL 🛡️", 
                 font=("Courier", 10), fg="#00cc00", bg="#0d0d0d")
footer.pack(pady=15)

# Status Bar
status_bar = tk.Label(root, text="Status: Ready | API: VirusTotal | Security Level: HIGH", 
                     font=("Courier", 9), fg="#00aa00", bg="#000000", anchor="w")
status_bar.pack(side=tk.BOTTOM, fill=tk.X)

# Main loop

root.mainloop()
