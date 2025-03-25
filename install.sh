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
    tool_name=$(echo "$tool" | awk -F/ '{print $NF}')
    go install -v "$tool@latest" && sudo cp ~/go/bin/$tool_name /usr/bin/$tool_name
done

go install -v github.com/hahwul/dalfox/v2@latest
sudo cp ~/go/bin/dalfox /usr/bin/dalfox

echo " [*] Cloning and installing Git-based tools..."
git clone https://github.com/1ndianl33t/Gf-Patterns
if [ -d "Gf-Patterns" ]; then
    mkdir -p ~/.gf
    mv Gf-Patterns/*.json ~/.gf/
else
    echo " [!] Gf-Patterns klasörü bulunamadı!"
fi

if [[ $SHELL == *"bash" ]]; then
    wget https://raw.githubusercontent.com/tomnomnom/gf/refs/heads/master/gf-completion.bash
    mv gf-completion.bash ~/.gf/gf-completion.bash
    echo 'source ~/.gf/gf-completion.bash' | sudo tee -a ~/.bashrc
elif [[ $SHELL == *"zsh" ]]; then
    wget https://raw.githubusercontent.com/tomnomnom/gf/refs/heads/master/gf-completion.zsh
    mv gf-completion.zsh ~/.gf/gf-completion.zsh
    echo 'source ~/.gf/gf-completion.zsh' | sudo tee -a ~/.zshrc
elif [[ $SHELL == *"fish" ]]; then
    wget https://raw.githubusercontent.com/tomnomnom/gf/refs/heads/master/gf-completion.zsh
    mv gf-completion.zsh ~/.gf/gf-completion.fish
    echo 'source ~/.gf/gf-completion.fish' | sudo tee -a ~/.config/fish/config.fish
fi


git clone https://github.com/defparam/smuggler.git
if [ -d "smuggler" ]; then
    sudo mv smuggler /opt/smuggler
    sudo chmod +x /opt/smuggler/smuggler.py
    sudo ln -sf /opt/smuggler/smuggler.py /usr/local/bin/smuggler
    rm -rf smuggler
else
    echo " [!] Smuggler yüklenemedi!"
fi

echo " [*] Installing Findomain..."
curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/bin/findomain
rm findomain-linux.zip

if [ -d "/tools/src/ex-tools/" ]; then
    for script in cors.py corscan.py csrfscan.py lfiscan.sh params.py redirectest.py ssrftest.py sstiscan.py; do
        sudo cp "/tools/src/ex-tools/$script" "/usr/bin/${script%.*}"
        sudo chmod +x "/usr/bin/${script%.*}"
    done
else
    echo " [!] /tools/src/ex-tools/ can't found!"
fi


rm -rf Gf-Patterns
rm -rf gf-completion.*
echo " [*] All tools installed!"
