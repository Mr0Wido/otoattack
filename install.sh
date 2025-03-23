#!/bin/bash

echo " [*] Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y unzip curl git golang sqlmap python3-pip pipx wfuzz gobuster masscan nmap sed dnsutils

echo " [*] Installing Go tools..."
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    "github.com/tomnomnom/assetfinder"
    "github.com/projectdiscovery/httpx/cmd/httpx"
    "github.com/tomnomnom/gf"
    "github.com/hahwul/dalfox/v2"
    "github.com/tomnomnom/waybackurls"
    "github.com/mlcsec/headi"
    "github.com/tomnomnom/qsreplace"
    "github.com/Hackmanit/Web-Cache-Vulnerability-Scanner"
    "github.com/glebarez/cero"
    "github.com/PentestPad/subzy"
    "github.com/ffuf/ffuf/v2"
    "github.com/lc/gau/v2/cmd/gau"
)

for tool in "${GO_TOOLS[@]}"; do
    go install -v "$tool@latest" && sudo cp ~/go/bin/$(basename "$tool") /usr/bin/$(basename "$tool")
done

echo " [*] Cloning and installing Git-based tools..."
git clone https://github.com/1ndianl33t/Gf-Patterns
sudo  mkdir ~/.gf
sudo  mv ~/Gf-Patterns/*.json ~/.gf
if [[ $SHELL == *"bash"]]; then 
    sudo wget https://raw.githubusercontent.com/tomnomnom/gf/refs/heads/master/gf-completion.bash
    sudo mv gf-completion.bash ~/.gf/gf-completion.bash
    sudo echo 'source ~/.gf/gf-completion.bash' >> ~/.bashrc
elif [[ $SHELL == *"zsh"]]; then
    sudo wget https://raw.githubusercontent.com/tomnomnom/gf/refs/heads/master/gf-completion.zsh
    sudo mv gf-completion.zsh ~/.gf/gf-completion.zsh
    sudo echo 'source ~/.gf/gf-completion.zsh' >> ~/.zshrc
elif [[ $SHELL == *"fish"]]; then
    sudo wget https://raw.githubusercontent.com/tomnomnom/gf/refs/heads/master/gf-completion.zsh
    sudo mv gf-completion.zsh ~/.gf/gf-completion.fish
    sudo echo 'source ~/.gf/gf-completion.fish' >> ~/.config/fish/config.fish
fi

git clone https://github.com/defparam/smuggler.git
sudo mv smuggler /opt/smuggler
sudo chmod +x /opt/smuggler/smuggler.py
sudo ln -sf /opt/smuggler/smuggler.py /usr/local/bin/smuggler
rm -rf smuggler

echo " [*] Installing Findomain..."
curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/bin/findomain
rm findomain-linux.zip

sudo cp /tools/src/ex-tools/cors.py /usr/bin/cors
sudo chmod +x /usr/bin/cors
sudo cp /tools/src/ex-tools/corscan.py /usr/bin/corscan
sudo chmod +x /usr/bin/corscan
sudo cp /tools/src/ex-tools/csrfscan.py /usr/bin/csrfscan
sudo chmod +x /usr/bin/csrfscan
sudo cp /tools/src/ex-tools/lfiscan.sh /usr/bin/lfiscan
sudo chmod +x /usr/bin/lfiscan
sudo cp /tools/src/ex-tools/params.py /usr/bin/params
sudo chmod +x /usr/bin/params
sudo cp /tools/src/ex-tools/redirectest.py /usr/bin/redirectest
sudo chmod +x /usr/bin/redirectest
sudo cp /tools/src/ex-tools/ssrftest.py /usr/bin/ssrftest
sudo chmod +x /usr/bin/ssrftest
sudo cp /tools/src/ex-tools/sstiscan.py /usr/bin/sstiscan
sudo chmod +x /usr/bin/sstiscan

echo " [*] All tools installed!"
xsrfprobe