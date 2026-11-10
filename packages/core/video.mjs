import {assert,DomainError,escapeHtml} from './validation.mjs';
export function parseYouTubeId(value) {
 if(value===null||value==='')return null;
 assert(typeof value==='string'&&value.length<2048,'invalid_video','Enter a YouTube URL or video ID.');
 if(/^[A-Za-z0-9_-]{11}$/.test(value))return value;
 let u;try{u=new URL(value);}catch{throw new DomainError('invalid_video','Enter a YouTube URL or video ID.');}
 assert(u.protocol==='https:'&&!u.username&&!u.password&&!u.port,'invalid_video','Only secure YouTube URLs are accepted.');
 let video;
 if(u.hostname==='youtu.be')video=u.pathname.slice(1);
 else if(['youtube.com','www.youtube.com','m.youtube.com','www.youtube-nocookie.com'].includes(u.hostname)){
  if(u.pathname==='/watch')video=u.searchParams.get('v');
  else video=u.pathname.match(/^\/(?:embed|shorts|live)\/([A-Za-z0-9_-]{11})\/?$/)?.[1];
 }
 assert(typeof video==='string'&&/^[A-Za-z0-9_-]{11}$/.test(video),'invalid_video','Only a single valid YouTube video is accepted.');return video;
}
export function videoPanel(slug, config, {localAssetExists=false}={}) {
 const video=parseYouTubeId(config.youtubeId);const title=escapeHtml(config.title);
 const local=config.temporaryLocalVideo;
 if(local!==undefined&&local!==null)assert(local==='/assets/issue-video-placeholder.mp4','invalid_local_video','Only the reviewed temporary issue-video asset may be embedded.');
 const hasLocal=Boolean(local&&localAssetExists);
 const temporaryYouTube=Boolean(video&&typeof config.temporaryLabel==='string'&&config.temporaryLabel.trim());
 if(local&&video)throw new DomainError('video_conflict','Configure either the temporary local video or a finalized YouTube video, not both.');
 assert(/^\/assets\/[a-z0-9-]+\.(svg|webp|png|jpg)$/.test(config.poster),'invalid_poster','Use a campaign-hosted poster.');
 return `<section class="issue-video-section" aria-labelledby="video-${slug}"><div class="wrap"><span class="eyebrow">${temporaryYouTube?'TEMPORARY VIDEO PREVIEW':"THE IDEA, IN PHILLIP'S WORDS"}</span><h1 id="video-${slug}" class="video-title">${title}</h1><div class="issue-video${video||hasLocal?'':' video-pending'}" data-video="${video||''}" data-title="${title}"><img src="${config.poster}" alt="" width="1600" height="900"><div class="video-shade"></div>${hasLocal?`<div class="issue-placeholder-label" role="note">TEMPORARY VIDEO PLACEHOLDER &middot; The video shown here is not an explanation of ${title}.</div><video controls playsinline preload="metadata" poster="${config.poster}" aria-label="Temporary illustrative video for ${title}"><source src="${local}" type="video/mp4">Your browser does not support MP4 video.</video>`:video?`${temporaryYouTube?'<div class="issue-placeholder-label" role="note">'+escapeHtml(config.temporaryLabel)+'</div>':''}<button class="video-play" type="button" aria-label="Play ${temporaryYouTube?'temporary video for ':''}${title} on YouTube"><span aria-hidden="true">&#9654;</span> Play video</button>`:`<div class="video-message"><span class="play-outline" aria-hidden="true">&#9654;</span><strong>${title}</strong><span>Phillip's video introduction is coming soon.</span><a href="#why">Read the proposal below &darr;</a></div>`}</div><p class="video-privacy">${hasLocal?'Temporary illustrative video, not the final issue presentation. Hosted by this campaign website; no third-party video provider is contacted.':video?(temporaryYouTube?'Temporary illustrative video, not the final issue presentation. Choosing Play connects to YouTube; nothing is loaded from YouTube before you choose to watch.':'Choosing Play connects to YouTube. Nothing is loaded from YouTube before you choose to watch.'):'The complete summary is available below. No video provider is contacted.'}</p>${config.transcript?`<details class="video-transcript"><summary>Read the transcript</summary><div>${escapeHtml(config.transcript).replace(/\n/g,'<br>')}</div></details>`:''}</div></section>`;
}
