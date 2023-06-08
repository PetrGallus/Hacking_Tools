# Hacking Tools
🚀*complete list of hacking tools*🚀
* [Steganography](##Steganography)
* [WebApp Pentesting](##WebApp-Pentesting)
* [Cryptography](##Cryptography)
* [Binary Exploitation](##Binary-Exploitation)
* [Reverse Engineering](##Reverse-Engineering)
* [Password Cracking](##Password-Cracking)
## Steganography
***StegAnalysis - General screening tools***
Tools to run in the beginning. Allow you to get a broad idea of what you are dealing with.
| Tool | Description | Command Example |
| -------- | -------- | -------- |
| [file](https://www.cyberciti.biz/faq/bash-file-command-not-found-how-to-install-file/) |  Check out what kind of file you have    | `file stego.jpg`|
| [exiftool](https://github.com/exiftool/exiftool) | Check out metadata of media files | `exiftool stego.jpg`
| [binwalk](https://github.com/ReFirmLabs/binwalk)     | Check out if other files are embedded/appended | `binwalk -e stego.jpg`
| [strings](https://github.com/glowyphp/strings)      | Check out if there are interesting readable characters in the file | `strings stego.jpg`
| [foremost](https://github.com/gerryamurphy/Foremost)     | Carve out embedded/appended files | `foremost stego.jpg`
| [pngcheck](https://github.com/wkliu19/pngcheck)     | Get details on a PNG file (or find out is is actually something else) | `pngcheck stego.png`
| [identify](https://github.com/pre-commit/identify)     | [GraphicMagick](http://www.graphicsmagick.org/) tool to check what kind of image a file is. Checks also if image is corrupted. | `identify -verbose stego.jpg`
| [ffmpeg](https://github.com/FFmpeg/FFmpeg)      | ffmpeg can be used to check integrity of audio files and let it report infos and errors | `ffmpeg -v info -i stego.mp3 -f null -` to recode the file and throw away the result
| [stegoVeritas](https://github.com/bannsec/stegoVeritas) | Images (JPG, PNG, GIF, TIFF, BMP) | A wide variety of simple and advanced checks. Check out `stegoveritas.py -h`. Checks metadata, creates many transformed images and saves them to a directory, Brute forces LSB, ... | `stegoveritas.py stego.jpg` to run all checks |
| [zsteg](https://github.com/zed-0xff/zsteg) | Images (PNG, BMP) - Detects various LSB stego, also openstego and the [Camouflage tool](http://camouflage.unfiction.com/) | `zsteg -a stego.jpg` to run all checks |
| [stegdetect](http://old-releases.ubuntu.com/ubuntu/pool/universe/s/stegdetect) | Images (JPG) - Performs statistical tests to find if a stego tool was used (jsteg, outguess, jphide, ...). Check out `man stegdetect` for details. | `stegdetect stego.jpg` |
| [stegbreak](https://linux.die.net/man/1/stegbreak) | Images (JPG) - Brute force cracker for JPG images. Claims it can crack `outguess`, `jphide` and `jsteg`. | `stegbreak -t o -f wordlist.txt stego.jpg`, use `-t o` for outguess, `-t p` for jphide or `-t j` for jsteg |
| [Steghide](http://steghide.sourceforge.net/) | Images (JPG, BMP) and Audio (WAV, AU) - Versatile and mature tool to encrypt and hide data. | `steghide eextract -sf stego.jpg`

***SteganoGraphy - Tools creating stego***
Tools designed to detect steganography in files. Mostly perform statistical tests. They will reveal hidden messages only in simple cases. However, they may provide hints what to look for if they find interesting irregularities.

|Tool          |File types                |Description       |How to hide    | How to recover |
|--------------|--------------------------|------------------|---------------|----------------|
| [AudioStego](https://github.com/danielcardeenas/AudioStego) | Audio (MP3 / WAV) | Details on how it works are in this [blog post](https://danielcardeenas.github.io/audiostego.html) | `hideme cover.mp3 secret.txt && mv ./output.mp3 stego.mp3` | `hideme stego.mp3 -f && cat output.txt` |
| [jphide/jpseek](http://linux01.gwdg.de/~alatham/stego.html) | Image (JPG) | Pretty old tool from [here](http://linux01.gwdg.de/~alatham/stego.html). Here, the version from [here](https://github.com/mmayfield1/SSAK) is installed since the original one crashed all the time. It prompts for a passphrase interactively! | `jphide cover.jpg stego.jpg secret.txt` | `jpseek stego.jpg output.txt` |
| [jsteg](https://github.com/lukechampine/jsteg) | Image (JPG) | LSB stego tool. Does not encrypt the message. | `jsteg hide cover.jpg secret.txt stego.jpg` | `jsteg reveal cover.jpg output.txt` |
| [mp3stego](http://www.petitcolas.net/steganography/mp3stego/) | Audio (MP3) | Old program. Encrypts and then hides a message (3DES encryption!). Windows tool running in Wine. Requires WAV input (may throw errors for certain WAV files. what works for me is e.g.: `ffmpeg -i audio.mp3 -flags bitexact audio.wav`). Important: use absolute path only! | `mp3stego-encode -E secret.txt -P password /path/to/cover.wav /path/to/stego.mp3` | `mp3stego-decode -X -P password /path/to/stego.mp3 /path/to/out.pcm /path/to/out.txt`
| [openstego](https://github.com/syvaidya/openstego) | Images (PNG) | Various LSB stego algorithms (check out this [blog](http://syvaidya.blogspot.de/)). Still maintained. | `openstego embed -mf secret.txt -cf cover.png -p password -sf stego.png` | `openstego extract -sf openstego.png -p abcd -xf output.txt ` (leave out -xf to create file with original name!) |
| [outguess](https://packages.debian.org/sid/utils/outguess) | Images (JPG) | Uses "redundant bits" to hide data. Comes in two versions: old=`outguess-0.13` taken from [here](https://github.com/mmayfield1/SSAK) and new=`outguess` from the package repos. To recover, you must use the one used for hiding. | `outguess -k password -d secret.txt cover.jpg stego.jpg` | `outguess  -r -k password stego.jpg output.txt` |
| [spectrology](https://github.com/solusipse/spectrology) | Audio (WAV) | Encodes an image in the spectrogram of an audio file. | `TODO` | Use GUI tool `sonic-visualiser` |
| [stegano](https://github.com/cedricbonhomme/Stegano) | Images (PNG) | Hides data with various (LSB-based) methods. Provides also some screening tools. | `stegano-lsb hide --input cover.jpg -f secret.txt -e UTF-8 --output stego.png` or `stegano-red hide --input cover.png -m "secret msg" --output stego.png` or `stegano-lsb-set hide --input cover.png -f secret.txt -e UTF-8 -g $GENERATOR --output stego.png` for various generators (`stegano-lsb-set list-generators`) | `stegano-lsb reveal -i stego.png -e UTF-8 -o output.txt` or `stegano-red reveal -i stego.png` or `stegano-lsb-set reveal -i stego.png -e UTF-8 -g $GENERATOR -o output.txt`
| [Steghide](http://steghide.sourceforge.net/) | Images (JPG, BMP) and Audio (WAV, AU) | Versatile and mature tool to encrypt and hide data. | `steghide embed -f -ef secret.txt -cf cover.jpg -p password -sf stego.jpg` | `steghide extract -sf stego.jpg -p password -xf output.txt`
| [cloackedpixel](https://github.com/livz/cloacked-pixel) | Images (PNG) | LSB stego tool for images | `cloackedpixel hide cover.jpg secret.txt password` creates `cover.jpg-stego.png` | `cloackedpixel extract cover.jpg-stego.png output.txt password`
| [LSBSteg](https://github.com/RobinDavid/LSB-Steganography) | Images (PNG, BMP, ...) in uncompressed formats | Simple LSB tools with very nice and readable Python code | `LSBSteg encode -i cover.png -o stego.png -f secret.txt` | `LSBSteg decode -i stego.png -o output.txt` |
| [f5](https://github.com/jackfengji/f5-steganography) | Images (JPG) | F5 Steganographic Algorithm with detailed info on the process | `f5 -t e -i cover.jpg -o stego.jpg -d 'secret message'` | `f5 -t x -i stego.jpg 1> output.txt` |
| [stegpy](https://github.com/dhsdshdhk/stegpy) | Images (PNG, GIF, BMP, WebP) and Audio (WAV) | Simple steganography program based on the LSB method | `stegpy secret.jpg cover.png` | `stegpy _cover.png`

## WebApp Pentesting

| 1. Reconnaissance | 2. Scanning/Enumeration | WebApp Proxies |
| -------- | -------- | -------- |
| **1/2 Dir Fuzzing** | **1/2 Tools**  | [Burpsuite](https://portswigger.net/) - Burpsuite is a graphical tool for testing Web application security ![](svg/Windows.svg)![](svg/linux.svg)![](svg/mac.svg)
| [Dirbuster](https://github.com/KajanM/DirBuster)| [wpscan] |[ZAP](https://github.com/zaproxy/zaproxy) One of the world’s most popular free security tools ![](svg/Windows.svg)![](svg/linux.svg)![](svg/mac.svg)(https://github.com/wpscanteam/wpscan) (for WordPress)
| [FeroxBuster](https://github.com/epi052/feroxbuster) (Brute force directories on a web server)  | [nmap](https://github.com/nmap/nmap) (open ports) | [Mitmproxy](https://github.com/mitmproxy/mitmproxy) - An interactive TLS-capable intercepting HTTP proxy for penetration testers and software developers. ![](svg/Windows.svg)![](svg/linux.svg)![](svg/mac.svg)
| [wfuzz](https://github.com/xmendez/wfuzz) | [Nikto](https://github.com/sullo/nikto) | [Proxify](https://github.com/projectdiscovery/proxify) - Swiss Army knife Proxy tool for HTTP/HTTPS traffic capture, manipulation, and replay on the go.
| **2/2 Online tools**  | [testssl.sh](https://github.com/drwetter/testssl.sh)
| [whois.domaintools.com](https://whois.domaintools.com) | **2/2 Online tools**
|[reverseip.domaintools.com](https://reverseip.domaintools.com) (web-based reverse DNS lookup) |[ipaddressguide.com/cidr](https://www.ipaddressguide.com/cidr)
|[searchdns.netcraft.com](https://searchdns.netcraft.com) (web-based DNS lookup)|[calculator.net/ip-subnet-calculator.html](https://www.calculator.net/ip-subnet-calculator.html)
|[search.censys.io](https://search.censys.io) (domain lookup)|[speedguide.net/ports.php](https://www.speedguide.net/ports.php)
|[crt.sh](https://crt.sh) (certificate fingerprinting)|[securityheaders.com](https://securityheaders.com)
|[commoncrawl.org](https://commoncrawl.org/the-data/get-started) (web crawl dumps)|[csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com) (Content Security Policy evaluator)
|[opendata.rapid7.com](https://opendata.rapid7.com) (scan dumps)
|[virustotal.com](https://www.virustotal.com/gui/home/search) (malware database lookup)
|[isithacked.com](http://isithacked.com)
|[haveibeenpwned.com](https://haveibeenpwned.com)
|[hackedlist.io](https://hackedlist.io)
|[intelx.io](https://intelx.io) (database breaches)
|[search.wikileaks.org](https://search.wikileaks.org)
|[archive.org](https://archive.org) (wayback machine)
|[pgp.circl.lu](https://pgp.circl.lu) (OpenPGP key server)
|[shodan.io](https://www.shodan.io) (IoT search engine) 


## Cryptography

## Binary Exploitation

## Reverse Engineering

## Password Cracking
### Identify Hash

| Tool | Description | Command Example |
| -------- | -------- | -------- |
| [hash-identifier](https://github.com/blackploit/hash-identifier)     | Software to identify the different types of hashes used to encrypt data and especially passwords.    | `hash-identifier`
| [name-that-hash](https://github.com/HashPals/Name-That-Hash)| Have you ever come across a hash such as `5f4dcc3b5aa765d61d8327deb882cf99` and wondered what type of hash that is? 🤔...Name-that-hash will name that hash type! | `nth --help`
### Useful Websites
* [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef)
* [onlinehashcrack.com](https://www.onlinehashcrack.com)
* [hashkiller.io/listmanager](https://hashkiller.io/listmanager) (has many other tools)
* [hashes.com/en/decrypt/hash](https://hashes.com/en/decrypt/hash) (has many other tools)
* [crackstation.net](https://crackstation.net)
* [weakpass.com/wordlist](https://weakpass.com/wordlist) (lots of password dumps)
* [packetstormsecurity.com/Crackers/wordlists](https://packetstormsecurity.com/Crackers/wordlists)

### Cracking Tools


| Tool | Description | Command Example |
| -------- | -------- | -------- |
| [hashcat](https://github.com/hashcat/hashcat) |  world's fastest and most advanced password recovery utility | **MD5 hashes:** `hashcat -m 0 -a 3 --session=cracking --force --status -O -o hashcat_results.txt hashes.txt` **NTLMv1 hashes:** `hashcat -m 5500 -a 3 --session=cracking --force --status -O -o hashcat_results.txt hashes.txt`
| [JohnTheRipper](https://github.com/openwall/john) | Its primary purpose is to detect weak Unix passwords. | `john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha1 crack.txt`
| [WiFi Cracking](https://github.com/mtalbugaey/WiFi-Cracking-Password-Tool) | The tool first will display a list of WiFi networks near to you (by utilizing pywifi python library) after choosing targeted wifi and insert a dictionary brute force file it will look for the password and once the cracking was successfully it will show the password. | 

