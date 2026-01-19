sudo apt update
sudo apt install amass assetfinder dnsenum dnsrecon fierce hakrawler nikto nuclei subfinder sublist3r 
sudo apt install golang-go
go install github.com/tomnomnom/waybackurls@latest
sudo mv $(go env GOPATH)/bin/waybackurls /usr/local/bin/
go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
sudo mv $(go env GOPATH)/bin/urlfinder /usr/local/bin/

