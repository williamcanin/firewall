# Simples Firewall para Arch Linux

Firewall simples com suporte a Squid.

# Requerimentos

* iptables
* systemd
* squid
* kmod

# Instalando

1 - Faça o clone e entre na pasta:

```
git clone --single-branch https://github.com/williamcanin/firewall.git
cd firewall
```

2 - Compile o firewall no **Arch Linux**:

```
makepkg -fc
```

3 - Instale o firewall:

```
sudo pacman -U firewall*.zst
```

# Configuração

Para adicionar mais regras no firewall, antes de compilar, abra o arquivo "*firewall.sh*" e adicione suas regras **Iptables** no bloco *PUT YOUR OTHER RULES HERE*.
> Você também pode querer editar algumas variáveis global no script de acordo com seu sistema.

O arquivo de configuração se encontra em **/etc/firewall.conf**.
Abre este arquivo com privilégio de root, e edite conforme sua rede, colocando IP, Interface, etc, antes de usá-lo.

# Usando firewall


1 - Inicie o firewall manualmente:

```
sudo systemctl start firewall.service
```

2 - Iniciando o firewall durante o boot:

```
sudo systemctl enable firewall.service
```

3 - Parando o firewall:

```
sudo systemctl stop firewall.service
```

4 - Reiniciando o firewall:

```
sudo systemctl restart firewall.service
```

5 - Desabilitando o firewall do boot:

```
sudo systemctl disable firewall.service
```