import {defineConfig} from 'vite';
import {fileURLToPath} from 'node:url';
import {releaseIntegrity} from './release-integrity.mjs';
// OpenPGP is used only by the lazily loaded protected-reports view. Keep it in its own
// stable vendor chunk so that view stays under the chunk budget and the library is
// cached independently of portal releases. It is never part of the initial load.
const vendorGroups=[
 {name:'vendor-openpgp',test:/[\\/]node_modules[\\/]openpgp[\\/]/},
];
export default defineConfig({plugins:[releaseIntegrity()],root:fileURLToPath(new URL('.',import.meta.url)),build:{outDir:'../../dist/portal',emptyOutDir:true,sourcemap:false,rolldownOptions:{output:{codeSplitting:{groups:vendorGroups}}}},server:{host:'127.0.0.1',port:4323,proxy:{'/api':'http://127.0.0.1:4322'}}});
