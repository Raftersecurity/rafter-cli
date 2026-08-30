import type { Extractor } from "./model.js";
import { stubExtractor } from "./stub-extractor.js";

/**
 * The extractor registry. W6/W7/W8 each append their extractor here and remove
 * the stub; nothing else in the CLI knows which extractors exist.
 */
export const EXTRACTORS: readonly Extractor[] = [stubExtractor];
