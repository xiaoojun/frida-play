import {
  isDisturbed,
  LegacyStream,
  Readable,
  Writable,
  Duplex,
  Transform,
  PassThrough,
  pipeline,
  addAbortSignal,
  finished,
  destroy,
  compose,
  promises,
} from 'readable-stream';

export default LegacyStream;
export {
  isDisturbed,
  LegacyStream as Stream,
  Readable,
  Writable,
  Duplex,
  Transform,
  PassThrough,
  pipeline,
  addAbortSignal,
  finished,
  destroy,
  compose,
  promises,
};
