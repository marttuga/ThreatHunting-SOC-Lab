# **T1687 (Exploitation for Defense Impairment)**

## **1. Identificação**

  -----------------------------------------------------------------------
  **Campo**              **Valor**
  ---------------------- ------------------------------------------------
  Hunt ID                HUNT-G3-002

  Técnica                T1687 - Exploitation for Defense Impairment

  Tática                 Defense Impairment

  Host(s) em scope       Finance01

  Prioridade             Alta
  -----------------------------------------------------------------------

## **2. Hipótese**

> *Se um adversário tentar comprometer os mecanismos de proteção do
> Windows através da desativação do Microsoft Defender, esperamos
> observar comandos PowerShell que alterem as definições de segurança,
> juntamente com eventos do Microsoft Defender que indiquem alterações
> ao estado da proteção em tempo real.*
>
> *Estes comportamentos distinguem-se da atividade administrativa
> legítima pela sequência de execução iniciada após o comprometimento do
> sistema e pela correlação com outras TTPs da cadeia de ataque.*

## **3. Contexto ATT&CK**

-   A técnica descreve ações destinadas a reduzir ou eliminar os
    mecanismos de defesa do sistema operativo, dificultando a deteção
    das atividades do atacante.

-   No cenário laboratorial, após a execução da macro maliciosa, foi
    utilizado PowerShell para desativar componentes do Microsoft
    Defender, incluindo a proteção em tempo real, análise comportamental
    e inspeção de scripts.

## **4. Fontes de telemetria**

  -----------------------------------------------------------------------
  **Fonte**        **ID / Canal**      **Campo Wazuh**
  ---------------- ------------------- ----------------------------------
  Microsoft        Windows Event Log   rule.id
  Defender                             

  Sysmon           ID 1 (Process       data.win.eventdata.image,
                   Create)             commandLine, parentImage
  -----------------------------------------------------------------------

## **5. Query de caça (DQL)**

rule.id : (100125 or 100128)

-   Janela: Last 30 minutes durante a simulação.

## **6. Linha de base vs. anomalia**

  -----------------------------------------------------------------------
  **Benigno esperado**                **Malicioso**
  ----------------------------------- -----------------------------------
  Alterações ao Defender efetuadas    Desativação da proteção em tempo
  por processos legítimos do Windows  real através de PowerShell.
  (Windows Update, manutenção do      
  sistema).                           

  Alterações ocasionais provocadas    Sequência iniciada após execução da
  por operações administrativas       macro maliciosa e correlacionada
  autorizadas.                        com outras TTPs.

  Eventos gerados por TiWorker.exe    Execução de comandos PowerShell
  durante operações do Windows        para alterar componentes do
  Update.                             Defender.
  -----------------------------------------------------------------------

## **7. Regra de deteção associada**

  --------------------------------------------------------------------------------
  **rule.id**   **rule.level**   **Lógica**
  ------------- ---------------- -------------------------------------------------
  100122        13               PowerShell desativa Defender via
                                 Set-MpPreference/Add-MpPreference

  100124        10               Alteração à configuração do Windows Defender

  100125        12               Proteção em tempo real desativada (Windows Event
                                 Log)

  100128        11               Exclusão adicionada ao Windows Defender
  --------------------------------------------------------------------------------

## **8. Validação**

-   **TP:** As regras 100125 e 100128 foram acionadas durante a execução
    da técnica, confirmando a desativação dos mecanismos de proteção do
    Microsoft Defender e validando a cadeia de deteção até ao TheHive.

-   **FP:** Durante a validação foi identificado um falso positivo
    provocado pelo processo legítimo TiWorker.exe (Windows Update), que
    pode gerar eventos semelhantes aos produzidos por tentativas de
    desativação do Defender. A diferenciação pode ser melhorada através
    da contextualização do processo-pai e da correlação com outras
    evidências da cadeia de ataque.

## **9. Registo de execuções**

  -------------------------------------------------------------------------
  **Data**     **TP**   **FP**            **Observações**
  ------------ -------- ----------------- ---------------------------------
  20/06/2026   Sim      1                 Falso positivo associado ao
                                          processo legítimo TiWorker.exe
                                          (Windows Update)

  -------------------------------------------------------------------------

## **10. Desfecho e lacunas**

-   Regras 100125 e 100128 mantidas.

-   Recomenda-se afinar a deteção através da contextualização pelo
    processo-pai (TiWorker.exe) e da correlação com a atividade
    PowerShell para reduzir falsos positivos.

-   Alertas encaminhados corretamente para o TheHive.

-   Lacuna: a deteção puramente comportamental (Sysmon e Windows Event
    Logs); a integração de mecanismos adicionais de validação e contexto
    poderá melhorar a precisão da deteção em ambientes de produção.
