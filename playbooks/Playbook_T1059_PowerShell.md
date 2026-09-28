# **T1059.001 (PowerShell)**

## **1. Identificação**

  -----------------------------------------------------------------------
  **Campo**              **Valor**
  ---------------------- ------------------------------------------------
  Hunt ID                HUNT-G3-001

  Técnica                T1059.001 - Command and Scripting Interpreter:
                         PowerShell

  Tática                 Execution

  Host(s) em scope       Finance01

  Prioridade             Alta
  -----------------------------------------------------------------------

## **2. Hipótese**

> *Se um adversário usar PowerShell após a execução da macro maliciosa,
> então\
> esperamos observar processos powershell.exe com flags de evasão (-enc)
> ou cradles de\
> download (DownloadString, IEX), lançados por um processo-pai invulgar
> (Office, browser, cmd).*
>
> *Distingue-se do uso legítimo porque normalmente o admin não recorre a
> comandos codificados em base64 nem executam PowerShell a partir de
> aplicações de utilizador.*

## **3. Contexto ATT&CK**

-   PowerShell é abusado para executar scripts, recolher informação e
    descarregar payloads, recorrendo a binários legítimos do sistema
    (LotL), o que dificulta a deteção por assinatura.

-   No laboratório, a cadeia é: documento Word com macro, abre janelas
    de PowerShell e executa scripts subsequentes (desativar Defender,
    alterar firewall).

## **4. Fontes de telemetria**

  -----------------------------------------------------------------------
  **Fonte**        **ID / Canal**      **Campo Wazuh**
  ---------------- ------------------- ----------------------------------
  Sysmon           ID 1 (Process       data.win.eventdata.image,
                   Create)             commandLine, parentImage

  -----------------------------------------------------------------------

## **5. Query de caça (DQL)**

data.win.eventdata.commandLine : (\*EncodedCommand\* or \*-enc\* or
\*FromBase64String\* or \*DownloadString\* or \*Invoke-Expression\* or
\*IEX\*)

-   Janela: Last 30 minutes durante a simulação.

## **6. Linha de base vs. anomalia**

  -------------------------------------------------------------------------
  **Benigno esperado**                **Malicioso**
  ----------------------------------- -------------------------------------
  PowerShell lançado por explorer.exe powershell.exe com -EncodedCommand
  por admin a abrir uma consola       

  Scripts de gestão assinados, sem    parent = winword.exe / outlook.exe
  flags de ocultação                  

  Módulos internos sem cradles de     IEX (New-Object
  rede                                Net.WebClient).DownloadString(\...)
  -------------------------------------------------------------------------

## **7. Regra de deteção associada**

  --------------------------------------------------------------------------------
  **rule.id**   **rule.level**   **Lógica**
  ------------- ---------------- -------------------------------------------------
  100111        10               PowerShell com flags de evasão

  100112        12               PowerShell com padrões maliciosos (iex,
                                 downloadstring, frombase64string)

  100113        8                PowerShell com parent suspeito
  --------------------------------------------------------------------------------

## **8. Validação**

-   **TP:** macro do cenário disparou as 3 regras; a 100112 (L12)
    confirmou o cradle de download. Cadeia validada ponta-a-ponta até ao
    TheHive .

-   **FP:** Não foram observados falsos positivos durante a validação
    deste cenário. Apesar disso, em ambientes de produção poderão
    ocorrer alertas legítimos associados à utilização administrativa de
    PowerShell, pelo que poderá ser considerada, futuramente, a criação
    de *allowlists* ou a contextualização pelo processo-pai.

## **9. Registo de execuções**

  --------------------------------------------------------------------------
  **Data**       **TP**   **FP**              **Observações**
  -------------- -------- ------------------- ------------------------------
  20/06/2026     Sim      0                   As regras dispararam conforme
                                              esperado durante a simulação.

  --------------------------------------------------------------------------

## **10. Desfecho e lacunas**

-   Regras 100111/100112 mantidas.

-   Regra 100113 mantida. Poderá futuramente beneficiar de exclusões
    específicas para ambientes de produção caso sejam observadas
    utilizações administrativas frequentes de PowerShell.

-   Encaminhada para TheHive.

-   Lacuna: deteção puramente comportamental (Sysmon + linha de
    comando); a camada de assinaturas de ficheiro fica como trabalho
    futuro para artefactos persistentes em disco.
