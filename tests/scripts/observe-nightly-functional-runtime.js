#!/usr/bin/env node
'use strict';
// Refuse before argument parsing, receipt reads, Docker or output creation.
function main(){throw Error('RETIRED_SIGNED_IMAGE_GENERATION');}
if(require.main===module){try{main();}catch(error){console.error(error.message);process.exitCode=1;}}
module.exports={main};
