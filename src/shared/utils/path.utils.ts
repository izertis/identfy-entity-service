import path, {resolve} from 'path';
import {fileURLToPath} from 'url';

const thisFilePath = fileURLToPath(import.meta.url);
const thisDirPath = path.dirname(thisFilePath);
// The relative path from this file to the base directory of the project.
// Fix this if the file is moved.
const relativePathToSrcDir = '../../';

/**
 * The base directory of the project.
 */
export const SRC_DIR = resolve(thisDirPath, relativePathToSrcDir);
