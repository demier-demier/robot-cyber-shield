import { createEngine } from './engine.js';
import { createScene } from './scene.js';

const $ = id => document.getElementById(id);
const order = ['authorized', 'tamper', 'camera', 'replay', 'telemetry'];
const seconds = 7;
let lang = 'en', engine, scene, evidence, current = 'authorized', result = null;
let ready = false, running = false, touring = false, progress = 0, previous = 0, lastError = null;
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
const en = Object.fromEntries([...document.querySelectorAll('[data-i18n]')].map(el => [el.dataset.i18n, el.innerHTML]));
const pt = {
 present:'Apresentar ⛶',
 brandSub:'PROTEÇÃO DE COMANDOS E DADOS', source:'Código-fonte ↗', eyebrow:'A PROTEÇÃO, DE UM JEITO QUE DÁ PARA VER', headline:'Controle o robô. Proteja o que ele vê.', intro:'Altere um comando. Tente acessar a câmera. Veja o que passa — e o que é barrado pela proteção.', tour:'Ver demonstração guiada', tourDuration:'5 cenas · cerca de 35 segundos · sem instalar', workcell:'CÉLULA DE TESTE', simulated:'Robô simulado', loading:'Carregando verificador Rust…', illustration:'ILUSTRAÇÃO VISUAL', robotLabel:'ROBÔ MÓVEL / R-01', sceneReady:'Aguardando um comando', normalShort:'Comando válido', normalTag:'Deixe o robô trabalhar', tamperShort:'Alterar comando', tamperTag:'Quebrar a assinatura', cameraShort:'Acessar a câmera', cameraTag:'Tentar ler os dados', replayShort:'Repetir comando', replayTag:'Tentar uma segunda vez', telemetryShort:'Compartilhar dados', telemetryTag:'Só o que é permitido', liveRust:'VERIFICAÇÃO RUST AO VIVO', evidenceLink:'Evidências ↓', request:'O PEDIDO', decision:'A DECISÃO DE SEGURANÇA', waiting:'Aguardando', startHint:'Escolha uma cena ou inicie a demonstração guiada.', outcome:'O QUE CHEGA AO ROBÔ', notRun:'Nenhum pedido executado', initialOutcome:'A animação acompanha o resultado da verificação.', runCase:'Executar esta cena', isolated:'Cada cena inicia uma sessão de demonstração nova.', takeawayInitial:'A proteção fica entre o pedido e o robô. Se uma verificação falhar, o comando não é encaminhado.', moreTests:'Experimente outro teste', speedTest:'Ultrapassar o limite de velocidade', holderTest:'Usar a chave errada', expiredTest:'Usar missão expirada', revokedTest:'Usar permissão revogada', evidenceEyebrow:'POR TRÁS DA DEMONSTRAÇÃO', evidenceTitle:'Um resultado visível. Um motivo verificável.', evidenceIntro:'As verificações de comandos executam o núcleo Rust do projeto no navegador. A cena da câmera mostra evidências registradas de processos ROS 2 reais.', proofCommand:'Comandos assinados, verificados localmente', proofCommandCopy:'Verificações reais de assinatura e política. Dados sintéticos originais. Relógio fixo e estado em memória nesta demo, separados do SQLite persistente do serviço nativo.', proofROS:'Acesso à câmera recusado pelo ROS 2', recorded:'TESTE REGISTRADO', proofLimits:'Robô simulado, limites explícitos', proofLimitsCopy:'A cena 3D ilustra as decisões; não é um teste de hardware nem uma medição de física. Não há conexão com robôs, câmeras ou sistemas de terceiros.', originalFixtures:'DADOS SINTÉTICOS', readResults:'Ver resultados medidos ↗', viewRun:'Inspecionar teste ROS 2 ↗', downloadEvidence:'Baixar esta decisão ↓', technicalDetails:'Evidências técnicas da cena selecionada', portfolio:'Explorar os outros projetos ↗'
};
Object.assign(pt, {
 present:'Modo foco ⛶', source:'Código ↗', eyebrow:'DEMONSTRAÇÃO INTERATIVA DE SEGURANÇA',
 headline:'Tente assumir o controle.', intro:'Altere um comando. Peça dados privados. Veja onde o acesso é barrado.',
 tour:'Ver a demonstração', simulated:'ROBÔ SIMULADO', loading:'Carregando verificador…',
 sceneLabel:'PROTEÇÃO DE COMANDOS E DADOS', illustration:'ILUSTRAÇÃO 3D',
 request:'PEDIDO RECEBIDO', decision:'DECISÃO DA PROTEÇÃO',
 tamperShort:'Adulterar o comando', tamperTag:'Alterar uma instrução assinada',
 cameraShort:'Acessar a câmera', cameraTag:'Pedir dados de sensores restritos',
 normalShort:'Missão autorizada', visualTiming:'Tempo ilustrativo',
 boundaryNote:'Rust verifica os comandos ao vivo. O acesso à câmera usa evidência registrada de ROS 2.',
 evidenceLink:'Inspecionar evidências ↓', evidenceTitle:'O que aconteceu e como verificar',
 proofCommand:'O que executa no navegador', proofROS:'Acesso à câmera: teste ROS 2 registrado',
 proofLimitsCopy:'O robô 3D ilustra o resultado. Nenhum robô físico, câmera ou sistema de terceiros está conectado.',
 moreTests:'Outras verificações', replayShort:'Repetir um comando', telemetryShort:'Reduzir a telemetria',
 readResults:'Resultados medidos ↗', viewRun:'Teste ROS 2 nativo ↗', technicalDetails:'Registro técnico da decisão', portfolio:'Outros projetos ↗'
});
const text = pair => pair[lang === 'pt' ? 1 : 0];
const t = key => lang === 'pt' ? (pt[key] ?? en[key] ?? key) : (en[key] ?? key);
const cases = {
 authorized: {
  title:['A legitimate instruction','Uma instrução legítima'], description:['An authorized operator asks the robot to move. The mission and each command must pass verification.','Um operador autorizado pede movimento. A missão e cada comando precisam passar pela verificação.'], request:['Move forward with a valid signed mission.','Avançar com uma missão assinada e válida.'], code:'signed mission + signed command', explanation:['The identity, signatures and motion limits match. The guard forwards the permitted commands.','A identidade, as assinaturas e os limites conferem. A proteção encaminha os comandos permitidos.'], outcome:['The robot can move.','O robô pode se mover.'], detail:['Only the verified commands are forwarded. Each permission has a short lifetime.','Só os comandos verificados são encaminhados. Cada autorização tem validade curta.'], takeaway:['Protection should let authorized work happen. A valid request passes through the guard.','A proteção deve permitir o trabalho autorizado. Um pedido válido passa pela verificação.'], caption:['Authorized motion','Movimento autorizado'], kind:'normal'
 },
 tamper: {
  title:['Change a signed command','Alterar um comando assinado'], description:['A command was signed for one speed. Someone changes its contents after it was signed.','Um comando foi assinado para uma velocidade. Alguém altera o conteúdo depois da assinatura.'], request:['Change the movement instruction without a new signature.','Alterar a instrução de movimento sem uma nova assinatura.'], code:'command edited → signature unchanged', explanation:['The signature no longer matches the command. The Rust verifier rejects it.','A assinatura não corresponde mais ao comando. O verificador Rust o rejeita.'], outcome:['No command reaches the robot.','Nenhum comando chega ao robô.'], detail:['The request is stopped at the guard. The illustrated robot remains still.','O pedido é barrado pela proteção. O robô ilustrado permanece parado.'], takeaway:['A signed command cannot be silently changed. Changing the payload breaks its proof.','Um comando assinado não pode ser alterado silenciosamente. A mudança invalida sua assinatura.'], caption:['Altered command blocked','Comando alterado bloqueado'], kind:'tamper'
 },
 camera: {
  title:['The camera is not public','A câmera não é pública'], description:['An analytics participant tries to subscribe to the robot’s raw sensor stream. Its role only permits minimal telemetry.','Um participante de análise tenta ler os sensores brutos do robô. Sua função permite apenas telemetria mínima.'], request:['Read raw camera and sensor data.','Ler dados brutos de câmera e sensores.'], code:'/robot/sensors/raw → read', explanation:['ROS 2 refused to create the reader because the topic was outside its permissions.','O ROS 2 recusou criar o leitor: o tópico estava fora das permissões daquele participante.'], outcome:['Raw data stays out of reach.','Os dados brutos ficam protegidos.'], detail:['This is recorded evidence from the native ROS 2 test. The authorized robot operation continued.','Esta é uma evidência registrada do teste ROS 2 nativo. A operação autorizada do robô continuou.'], takeaway:['Permission to view battery status is not permission to read a camera. Those routes have separate access rules.','Permissão para ver a bateria não dá acesso à câmera. Esses caminhos têm regras de acesso separadas.'], caption:['Camera access blocked · authorized work continues','Câmera bloqueada · trabalho autorizado continua'], kind:'camera'
 },
 replay: {
  title:['A command is not a free pass','Um comando não é um passe livre'], description:['The same valid signed command is submitted twice. A correct signature alone must not allow repetition.','O mesmo comando válido é enviado duas vezes. Uma assinatura correta não deve permitir repetição.'], request:['Deliver the exact same command a second time.','Entregar o mesmo comando pela segunda vez.'], code:'sequence 1 → sequence 1 again', explanation:['The first request is accepted. Its sequence is consumed; the repeated request is rejected.','O primeiro pedido é aceito. Sua sequência é consumida; a repetição é rejeitada.'], outcome:['One permission. No second movement.','Uma autorização. Nenhum segundo movimento.'], detail:['The duplicate cannot renew the first command’s lifetime. The short original movement ends.','A cópia não renova a validade do primeiro comando. O movimento original termina.'], takeaway:['A captured command cannot be reused to keep the robot moving. The verifier remembers it was already admitted.','Um comando capturado não pode ser reutilizado para manter o robô em movimento. O verificador registra que já o aceitou.'], caption:['First allowed · duplicate blocked','Primeiro aceito · repetição bloqueada'], kind:'replay'
 },
 telemetry: {
  title:['Share what is useful','Compartilhar o que é útil'], description:['An authorized sensor submits operational data with private fields. The guard builds a new, restricted output.','Um sensor autorizado envia dados operacionais junto de campos privados. A proteção produz uma saída restrita.'], request:['Export status and battery — not raw recordings.','Exportar estado e bateria — não gravações brutas.'], code:'sensor data → explicit output allowlist', explanation:['The signed sensor request is valid. Only the approved output fields are returned.','O pedido assinado do sensor é válido. Somente os campos aprovados são devolvidos.'], outcome:['Useful telemetry, without raw content.','Telemetria útil, sem conteúdo bruto.'], detail:['Status, battery and coarse position cells are shared. Camera, audio and operator identity are excluded.','Estado, bateria e posição aproximada são compartilhados. Câmera, áudio e identidade do operador são excluídos.'], takeaway:['Data protection happens before sharing. The guard creates an approved output instead of hiding fields in a screen.','A proteção acontece antes de compartilhar. O sistema cria uma saída permitida, em vez de apenas esconder campos na tela.'], caption:['Minimal telemetry shared · raw fields withheld','Telemetria mínima compartilhada · dados brutos retidos'], kind:'telemetry'
 },
 overspeed: {
  title:['A valid signature has limits','Uma assinatura válida tem limites'], description:['Even an authorized operator cannot exceed the configured mission speed.','Mesmo um operador autorizado não pode exceder a velocidade permitida para a missão.'], request:['Request motion above the permitted speed.','Pedir movimento acima da velocidade permitida.'], code:'requested speed > mission limit', explanation:['The signature is valid, but the requested speed is outside the policy. The command is refused.','A assinatura é válida, mas a velocidade está fora da política. O comando é recusado.'], outcome:['No excessive-speed command is forwarded.','Nenhum comando acima do limite é encaminhado.'], detail:['Authentication and movement limits are independent checks. Both must pass.','Autenticação e limites de movimento são verificações independentes. Ambas precisam passar.'], takeaway:['Authorization is bounded. A legitimate credential does not give unlimited control of the robot.','A autorização tem limites. Uma credencial legítima não dá controle irrestrito do robô.'], caption:['Speed-limit violation blocked','Velocidade acima do limite bloqueada'], kind:'speed'
 },
 wrong_holder: {
  title:['The wrong key cannot command','A chave errada não comanda'], description:['Someone has a signed mission grant, but cannot prove possession of the holder’s private key.','Alguém possui uma missão assinada, mas não comprova ter a chave privada de seu titular.'], request:['Use a signature from a different holder.','Usar uma assinatura de outro titular.'], code:'request signer ≠ authorized holder', explanation:['The request proof does not match the holder bound to the mission. Verification fails.','A prova não corresponde ao titular definido na missão. A verificação falha.'], outcome:['No command is forwarded.','Nenhum comando é encaminhado.'], detail:['A copied mission grant alone is insufficient to control the robot.','Uma cópia da missão assinada, sozinha, não basta para controlar o robô.'], takeaway:['Both permission and proof of key possession are required for a command to pass.','São necessárias a permissão e a prova de posse da chave para o comando passar.'], caption:['Wrong signing key blocked','Chave de assinatura errada bloqueada'], kind:'tamper'
 },
 expired: {
  title:['An old mission cannot authorize','Uma missão expirada não autoriza'], description:['The command is signed, but its mission grant has already expired on the demo clock.','O comando está assinado, mas sua missão já expirou no relógio da demonstração.'], request:['Use a mission after its expiration.','Usar uma missão após sua expiração.'], code:'mission expiry < demo clock', explanation:['The mission is outside its validity period. The guard rejects the command.','A missão está fora do prazo de validade. A proteção rejeita o comando.'], outcome:['Expired permission grants no movement.','Permissão expirada não permite movimento.'], detail:['Signature verification does not extend a mission’s validity.','A verificação de assinatura não estende a validade de uma missão.'], takeaway:['Temporary permissions end when their mission expires. The fixed demo clock makes this test repeatable.','Permissões temporárias terminam quando a missão expira. O relógio fixo torna o teste reproduzível.'], caption:['Expired mission blocked','Missão expirada bloqueada'], kind:'tamper'
 },
 revoked: {
  title:['Revoked means revoked','Revogada significa revogada'], description:['The operator withdraws a previously issued permission before the next request.','O operador retira uma permissão previamente emitida antes do próximo pedido.'], request:['Attempt a command using revoked permission.','Tentar um comando com uma permissão revogada.'], code:'valid signature + revoked mission', explanation:['The grant is on the revocation list. Its signature cannot override that decision.','A missão está na lista de revogações. Sua assinatura não sobrepõe essa decisão.'], outcome:['The revoked mission cannot move the robot.','A missão revogada não move o robô.'], detail:['This browser session uses an in-memory revocation list. The native service persists it in SQLite.','Esta sessão usa uma lista em memória. O serviço nativo mantém a revogação em SQLite.'], takeaway:['Permission can be withdrawn. A valid signature is only one part of the authorization decision.','A permissão pode ser retirada. Uma assinatura válida é apenas uma parte da decisão de autorização.'], caption:['Revoked permission blocked','Permissão revogada bloqueada'], kind:'tamper'
 }
};

Object.assign(cases.authorized, {
 title:['Authorized mission.','Missão autorizada.'], code:'velocity: 0.25 m/s · signed',
 outcome:['Verified commands reach the robot.','Comandos verificados chegam ao robô.'],
 takeaway:['Now try changing the command or requesting restricted sensor data.','Agora tente alterar o comando ou pedir dados restritos dos sensores.']
});
Object.assign(cases.tamper, {
 title:['Command tampering.','Comando adulterado.'],
 code:'0.25 → 0.45 m/s\nsignature: unchanged',
 request:['Same signature. Different command.','Mesma assinatura. Comando diferente.'],
 outcome:['The altered command never reaches the robot.','O comando adulterado não chega ao robô.'],
 takeaway:['Its signature no longer matches. The robot receives no movement instruction.','A assinatura não confere. O robô não recebe a instrução de movimento.']
});
Object.assign(cases.camera, {
 title:['Restricted camera access.','Acesso restrito à câmera.'],
 code:'READ /robot/sensors/raw\nrole: analytics',
 request:['This role can read status, not raw sensors.','Esta função pode ler o estado, não os sensores brutos.'],
 outcome:['Camera access refused. Authorized work continues.','Câmera protegida. O trabalho autorizado continua.'],
 takeaway:['ROS 2 refused the restricted reader. Permitted readers still received their data.','O ROS 2 recusou o leitor restrito. Os leitores autorizados continuaram recebendo dados.']
});
function setText(id, value) { $(id).textContent = value; }
function applyLanguage() {
 document.documentElement.lang = lang;
 scene?.setLanguage?.(lang);
 document.querySelectorAll('[data-i18n]').forEach(el => { el.innerHTML = t(el.dataset.i18n); });
 document.querySelectorAll('[data-lang]').forEach(el => { const selected = el.dataset.lang === lang; el.classList.toggle('selected', selected); el.setAttribute('aria-pressed', String(selected)); });
 updateStaticEvidence(); renderResult(); updateControls(); if(lastError)paintFailure();
}
function updateStaticEvidence() {
 if (!evidence) return;
 const c = evidence.access.camera;
 setText('camera-evidence-copy', text([
  `The unauthorized raw-data reader was refused. The authorized reader received ${c.authorizedRawReaderMessages} samples while the permitted minimal-data reader received ${c.minimalReaderMessages}. ${evidence.checks.passed}/${evidence.checks.total} native checks passed.`,
  `O leitor não autorizado de dados brutos foi recusado. O leitor autorizado recebeu ${c.authorizedRawReaderMessages} amostras e o leitor de dados mínimos recebeu ${c.minimalReaderMessages}. ${evidence.checks.passed}/${evidence.checks.total} verificações nativas passaram.`
 ]));
}
function renderResult() {
 const c = cases[current];
 setText('case-title', text(c.title)); setText('case-description', text(c.description));
 setText('request-copy', text(c.request)); setText('request-code', c.code);
 const recorded = current === 'camera';
 setText('verification-kind', recorded ? text(['RECORDED ROS 2 TEST','TESTE ROS 2 REGISTRADO']) : t('liveRust'));
 $('verification-kind').classList.toggle('recorded', recorded);
 document.querySelectorAll('[data-case]').forEach(el => { const selected = el.dataset.case === current; el.classList.toggle('active', selected); el.setAttribute('aria-pressed', String(selected)); });
 setText('scene-number', order.includes(current) ? `${String(order.indexOf(current)+1).padStart(2,'0')} / 05` : text(['EXTRA CHECK','TESTE EXTRA']));
 if (!result) return;
 const allowed = result.decision.allowed;
 const state = allowed ? 'allowed' : 'blocked';
 $('decision-box').dataset.state = state; $('scene-badge').dataset.state = state;
 setText('decision-icon', allowed ? '✓' : '×');
 const label = current === 'replay' ? text(['Duplicate blocked','Repetição bloqueada']) : allowed ? text(['Allowed','Permitido']) : text(['Blocked','Bloqueado']);
 setText('decision-title', label); setText('scene-badge', label.toUpperCase());
 setText('decision-explanation', text(c.explanation)); setText('reason-code', result.decision.reason);
 setText('outcome-title', text(c.outcome)); setText('outcome-copy', text(c.detail));
 setText('takeaway', text(c.takeaway)); setText('scene-caption', text(c.caption));
 $('data-preview').replaceChildren(); $('data-preview').hidden = !['camera','telemetry'].includes(current);
 if (current === 'camera') {
  addDataRow(text(['Raw camera access','Acesso à câmera bruta']),text(['DENIED','NEGADO']),false);
  addDataRow(text(['Authorized operation','Operação autorizada']),text(['CONTINUES','CONTINUA']),true);
 } else if (current === 'telemetry') {
  const data = result.decision.telemetry;
  if (data) {
   addDataRow(text(['Battery','Bateria']),`${data.battery_percent}%`,true);
   addDataRow(text(['Position','Posição']),text(['Coarse cells only','Só células aproximadas']),true);
   addDataRow(text(['Camera / audio / identity','Câmera / áudio / identidade']),text(['REMOVED','REMOVIDOS']),false);
  }
 }
 setText('technical-output', JSON.stringify(result, null, 2));
 $('download-evidence').disabled = !result;
}
function addDataRow(label,value,safe) {
 const row=document.createElement('div');row.className=safe?'safe-data':'private-data';
 const left=document.createElement('span'),right=document.createElement('strong');left.textContent=label;right.textContent=value;row.append(left,right);$('data-preview').append(row);
}
function updateControls() {
 const presenting=document.body.classList.contains('presentation-mode');
 $('presentation-button').textContent=presenting?text(['Exit presentation ✕','Sair da apresentação ✕']):t('present');
 $('presentation-button').setAttribute('aria-pressed',String(presenting));
 if (ready) { setText('engine-state',text(['Rust verifier ready · runs locally','Verificador Rust pronto · execução local'])); $('engine-state').classList.add('ready'); }
 $('tour-button').disabled = !ready; $('run-button').disabled = !ready; $('play-pause').disabled = !ready; $('progress').disabled = !ready;
 $('tour-button').querySelector('[data-i18n]').textContent = touring ? text(['Pause guided demo','Pausar demonstração']) : t('tour');
 $('tour-button').querySelector('.play-icon').textContent = touring ? 'Ⅱ' : '▶';
 $('play-pause').textContent = running ? 'Ⅱ' : '▶';
 $('play-pause').setAttribute('aria-label',running ? text(['Pause animation','Pausar animação']) : text(['Play animation','Reproduzir animação']));
 $('run-button').textContent = result ? text(['Run this scene again','Executar esta cena novamente']) : t('runCase');
}
function cameraResult() {
 const c = evidence.access.camera;
 if (evidence.evidenceReplay !== true || c.allowed !== false || c.nativeEndpointCreated !== false || c.participantInitialized !== true || !(c.authorizedRawReaderMessages>0)) throw new Error('Recorded ROS evidence failed its required positive control.');
 return {id:'camera', mode:'recorded-ros2-evidence', evidenceKind:'native-dds-test-replay', evidenceReplay:true,
  decision:{allowed:false,reason:'dds_topic_access_denied'}, source:evidence.source,
  access:c, observedRobot:evidence.cases.baseline,
  presentation:'Illustration of a recorded test. No live DDS participant or camera exists in this browser.'};
}
function selectCase(id, play=true, preserveTour=false) {
 if (!ready || !cases[id]) return;
 if (!preserveTour) touring=false;
 try {
  current=id; result=id==='camera'?cameraResult():engine.runScenario(id);
  const c=cases[id];
  let distance=0, movement=false;
  if(id==='camera'){distance=evidence.cases.baseline.maxDisplacementM;movement=true;}
  else {
   const accepted=(result.decisions||[]).filter(d=>d.allowed&&d.command);
   movement=accepted.length>0;
   distance=result.renderer?.distanceM ?? ((result.renderer?.linearMps||0)*(result.renderer?.durationMs||0)/1000);
   if(id==='replay' && accepted.length) {
    const command=accepted[0].command;
    distance=result.renderer?.distanceM ?? Math.abs(command.linear_mps)*0.25;
   }
  }
  scene?.reset();scene?.setMode({kind:c.kind,allowed:result.decision.allowed,distanceM:distance,movementAllowed:movement});
  progress=0;running=play;previous=0;scene?.setPaused(reducedMotion||!running);
  renderResult(); updateControls(); renderProgress();
 } catch(error) { fail(error); }
}
function renderProgress() {
 $('progress').value=String(Math.round(progress*1000));
 setText('playback-time',`0:${String(Math.floor(progress*seconds)).padStart(2,'0')} / 0:07`);
 scene?.setProgress(reducedMotion ? 1 : progress);
 const attack=result && !result.decision.allowed && current!=='replay';
 $('packet-label').hidden=!(attack&&progress>.23&&progress<.73);
 $('packet-label').textContent=current==='camera'?text(['Raw data access denied','Acesso aos dados brutos negado']):text(['Request blocked here','Pedido bloqueado aqui']);
}
function animate(now) {
 if(running) {
  if(previous)progress=Math.min(1,progress+(now-previous)/(seconds*1000));
  renderProgress();
  if(progress>=1) {
   if(touring && order.indexOf(current)<order.length-1)selectCase(order[order.indexOf(current)+1],true,true);
   else {running=false;touring=false;scene?.setPaused(true);updateControls();}
  }
 }
 previous=now;
 requestAnimationFrame(animate);
}
function fail(error) {
 lastError=error?.message||String(error);result=null;ready=false;running=false;touring=false;progress=0;
 scene?.reset();scene?.setMode({kind:'tamper',allowed:false,distanceM:0});scene?.setPaused(true);
 paintFailure();
}
function paintFailure() {
 const message=text(['The verifier could not complete this scene. No allowed result has been substituted. Reload the page to retry.','O verificador não concluiu esta cena. Nenhum resultado permitido foi substituído. Recarregue a página para tentar novamente.']);
 $('error-message').hidden=false;setText('error-message',message);
 setText('engine-state',text(['Verification unavailable','Verificação indisponível']));
 $('engine-state').classList.remove('ready');
 $('decision-box').dataset.state='blocked';setText('decision-title',text(['Not verified','Não verificado']));setText('decision-explanation',message);
 setText('technical-output',JSON.stringify({error:lastError,failClosed:true},null,2));
 $('download-evidence').disabled=true;$('progress').disabled=true;$('data-preview').hidden=true;$('packet-label').hidden=true;
 $('scene-badge').dataset.state='blocked';setText('scene-badge',text(['NOT VERIFIED','NÃO VERIFICADO']));
 setText('scene-caption',text(['Verification unavailable','Verificação indisponível']));
 setText('outcome-title',text(['No verified output','Nenhuma saída verificada']));setText('outcome-copy',message);setText('reason-code','');
 $('tour-button').disabled=true;$('run-button').disabled=true;$('play-pause').disabled=true;
}

$('presentation-button').addEventListener('click',()=>{document.body.classList.toggle('presentation-mode');updateControls();scene?.resize();});
$('tour-button').addEventListener('click',()=>{if(!ready)return;if(touring){touring=false;running=false;scene?.setPaused(true);updateControls();}else{document.body.classList.add('presentation-mode');touring=true;selectCase('authorized',true,true);scene?.resize();}});
$('run-button').addEventListener('click',()=>selectCase(current,true));
$('play-pause').addEventListener('click',()=>{if(!ready)return;if(!result||progress>=1){selectCase(current,true);return;}running=!running;touring=false;previous=0;scene?.setPaused(reducedMotion||!running);updateControls();});
document.querySelectorAll('[data-case]').forEach(el=>el.addEventListener('click',()=>selectCase(el.dataset.case,true)));
document.querySelectorAll('[data-lang]').forEach(el=>el.addEventListener('click',()=>{lang=el.dataset.lang;applyLanguage();}));
$('progress').addEventListener('input',event=>{running=false;touring=false;progress=Number(event.target.value)/1000;scene?.setPaused(true);renderProgress();updateControls();});
$('evidence-jump').addEventListener('click',()=>{document.body.classList.remove('presentation-mode');$('evidence-section').open=true;updateControls();scene?.resize();$('evidence-section').scrollIntoView({behavior:reducedMotion?'instant':'smooth'});});
$('download-evidence').addEventListener('click',()=>{if(!result)return;const blob=new Blob([JSON.stringify(result,null,2)+'\n'],{type:'application/json'});const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download=`robot-shield-${current}-decision.json`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
document.addEventListener('visibilitychange',()=>{if(document.hidden&&running){running=false;touring=false;scene?.setPaused(true);updateControls();}});
document.addEventListener('keydown',event=>{if(event.key==='Escape'){document.body.classList.remove('presentation-mode');scene?.resize();running=false;touring=false;scene?.setPaused(true);updateControls();}});

requestAnimationFrame(animate);
try {
 const data=await fetch('./data/ros-evidence.json');if(!data.ok)throw new Error('ROS evidence could not be loaded.');evidence=await data.json();
 [engine,scene]=await Promise.all([createEngine(),createScene($('scene-stage'))]);
 ready=true;updateStaticEvidence();selectCase('authorized',false);updateControls();
 // Stable, read-only observability hook for acceptance tests, never a security API.
 window.robotShieldDemo={getState:()=>({ready,caseId:current,mode:result?.mode,allowed:result?.decision?.allowed,reason:result?.decision?.reason,progress,running,touring,language:lang,webgl:scene?.available!==false}),getEvidence:()=>structuredClone(result)};
} catch(error) {fail(error);}
