## -*- coding: UTF-8 -*-
## prefetch.py
##
## Copyright (c) 2018 analyzeDFIR
## 
## Permission is hereby granted, free of charge, to any person obtaining a copy
## of this software and associated documentation files (the "Software"), to deal
## in the Software without restriction, including without limitation the rights
## to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
## copies of the Software, and to permit persons to whom the Software is
## furnished to do so, subject to the following conditions:
## 
## The above copyright notice and this permission notice shall be included in all
## copies or substantial portions of the Software.
## 
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
## IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
## FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
## AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
## LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
## OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
## SOFTWARE.

import logging
Logger = logging.getLogger(__name__)
from os import path
from io import BytesIO
from construct.lib import Container

try:
    from lib.parsers import FileParser
    from lib.parsers.utils import StructureProperty, WindowsTime
    from decompress import DecompressWin10
    from structures import prefetch as pfstructs
except ImportError:
    from .lib.parsers import FileParser
    from .lib.parsers.utils import StructureProperty, WindowsTime
    from .decompress import DecompressWin10
    from .structures import prefetch as pfstructs

class Prefetch(FileParser):
    '''
    Class for parsing Windows prefetch files
    '''
    header = StructureProperty(0, 'header')
    file_info = StructureProperty(1, 'file_info', deps=['header'])
    file_metrics = StructureProperty(2, 'file_metrics', deps=['header'])
    filename_strings = StructureProperty(3, 'filename_strings', deps=['header', 'file_info', 'file_metrics'])
    trace_chains = StructureProperty(4, 'trace_chains', deps=['header', 'file_info'])
    volumes_info = StructureProperty(5, 'volumes_info', deps=['header', 'file_info'])
    file_references = StructureProperty(6, 'file_references', deps=['file_info', 'volumes_info'])
    directory_strings = StructureProperty(7, 'directory_strings', deps=['file_info', 'volumes_info'])

    def _parse_directory_strings(self, stream=None):
        '''
        Args:
            stream: TextIOWrapper|BytesIO   => stream to read from
        Returns:
            List<Container<String, Integer|String>>
            List of directory strings and their lengths
        Preconditions:
            stream is of type TextIOWrapper or BytesIO          (assumed True)
        '''
        original_position = stream.tell()
        try:
            directory_strings = list()
            for volumes_info_entry in self.volumes_info:
                directory_strings_entry = list()
                stream.seek(self.file_info.SectionDOffset + volumes_info_entry.SectionFOffset)
                for i in range(volumes_info_entry.SectionFStringsCount):
                    try:
                        directory_string_length = pfstructs.Int16ul.parse_stream(stream)
                        directory_string = stream.read(directory_string_length * 2 + 2).decode('UTF16')
                        directory_strings_entry.append(directory_string.strip('\x00'))
                    except Exception as e:
                        Logger.error('Error parsing directory strings entry (%s)'%str(e))
                        directory_strings_entry.append(None)
                directory_strings.append(directory_strings_entry)
            return self._clean_value(directory_strings)
        finally:
            stream.seek(original_position)
    def _parse_file_references(self, stream=None):
        '''
        Args:
            stream: TextIOWrapper|BytesIO               => stream to read from
        Returns:
            List<Container<String, Any>>
            List of file references (see: src.structures.prefetch.PrefetchFileReferences)
        Preconditions:
            stream is of type TextIOWrapper or BytesIO          (assumed True)
        '''
        original_position = stream.tell()
        try:
            file_refs = list()
            for volumes_info_entry in self.volumes_info:
                try:
                    stream.seek(self.file_info.SectionDOffset + volumes_info_entry.SectionEOffset)
                    file_refs_entry = pfstructs.PrefetchFileReferences.parse_stream(stream)
                    file_refs_entry.References = list(map(lambda ref: Container(**ref), file_refs_entry.References))
                    file_refs.append(file_refs_entry)
                except Exception as e:
                    Logger.error('Error parsing file_refs_entry (%s)'%str(e))
                    file_refs.append(None)
            return self._clean_value(file_refs)
        finally:
            stream.seek(original_position)
    def _parse_volumes_info(self, stream=None):
        '''
        Args:
            stream: TextIOWrapper|BytesIO       => stream to read from
        Returns:
            List<Container<String, Any>>
            Prefetch file volumes information (see src.structures.prefetch.PrefetchVolumeInformation*)
        Preconditions:
            stream is of type TextIOWrapper or BytesIO  (assumed True)
        '''
        original_position = stream.tell()
        try:
            stream.seek(self.file_info.SectionDOffset)
            if self.header.Version == 'XP':
                PrefetchVolumeInformation = pfstructs.PrefetchVolumeInformation17
            elif self.header.Version == 'SEVEN':
                PrefetchVolumeInformation = pfstructs.PrefetchVolumeInformation23
            elif self.header.Version == 'EIGHT':
                PrefetchVolumeInformation = pfstructs.PrefetchVolumeInformation26
            else:
                PrefetchVolumeInformation = pfstructs.PrefetchVolumeInformation30
            volumes_info = list()
            for i in range(self.file_info.SectionDEntriesCount):
                volumes_info_entry = PrefetchVolumeInformation.parse_stream(stream)
                volumes_info_position = stream.tell()
                volumes_info_entry.VolumeCreateTime = WindowsTime.parse_filetime(volumes_info_entry.RawVolumeCreateTime)
                stream.seek(self.file_info.SectionDOffset + volumes_info_entry.VolumeDevicePathOffset)
                volumes_info_entry.VolumeDevicePath = pfstructs.PaddedString(
                    volumes_info_entry.VolumeDevicePathLength,
                    encoding='utf8').parse(
                        stream.read(volumes_info_entry.VolumeDevicePathLength*2).replace(b'\x00', b'')
                    )
                volumes_info.append(volumes_info_entry)
                stream.seek(volumes_info_position)
            return self._clean_value(volumes_info)
        finally:
            stream.seek(original_position)
    def _parse_filename_strings(self, stream=None):
        '''
        Args:
            stream: TextIOWrapper|BytesIO               => stream to read from
        Returns:
            List<String>
            List of filename strings associated with file_metrics array
        Preconditions:
            stream is of type TextIOWrapper or BytesIO  (assumed True)
        '''
        original_position = stream.tell()
        try:
            stream.seek(self.file_info.SectionCOffset)
            filename_strings = list()
            for file_metric in self.file_metrics:
                if (stream.tell() - self.file_info.SectionCOffset) <= self.file_info.SectionCLength:
                    filename_strings.append(
                        pfstructs.PrefetchFileNameString.parse_stream(stream)
                    )
                else:
                    filename_strings.append(None)
            return self._clean_value(filename_strings)
        finally:
            stream.seek(original_position)
    def _parse_trace_chains(self, stream=None):
        '''
        Args:
            stream: TextIOWrapper|BytesIO   => stream to read from
        Returns:
            List<Container<String, Any>>
            Prefetch file trace chains information array (see: src.structures.prefetch.PrefetchTraceChainEntry)
        Preconditions:
            stream is of type TextIOWrapper or BytesIO  (assumed True)
        '''
        original_position = stream.tell()
        try:
            stream.seek(self.file_info.SectionBOffset)
            trace_chains = list()
            for i in range(self.file_info.SectionBEntriesCount):
                trace_chains.append(pfstructs.PrefetchTraceChainEntry.parse_stream(stream))
            return self._clean_value(trace_chains)
        finally:
            stream.seek(original_position)
    def _parse_file_metrics(self, stream=None):
        '''
        Args:
            stream: TextIOWrapper|BytesIO       => stream to read from
        Returns:
            List<Container<String, Any>>
            Prefetch file metrics information array (see: src.structures.prefetch.PrefetchFileMetrics*)
        Preconditions:
            stream is of type TextIOWrapper or BytesIO  (assumed True)
        '''
        original_position = stream.tell()
        try:
            stream.seek(self.file_info.SectionAOffset)
            if self.header.Version == 'XP':
                PrefetchFileMetricsEntry = pfstructs.PrefetchFileMetricsEntry17
            elif self.header.Version == 'SEVEN':
                PrefetchFileMetricsEntry = pfstructs.PrefetchFileMetricsEntry23
            elif self.header.Version == 'EIGHT':
                PrefetchFileMetricsEntry = pfstructs.PrefetchFileMetricsEntry26
            else:
                PrefetchFileMetricsEntry = pfstructs.PrefetchFileMetricsEntry30
            file_metrics = list()
            for i in range(self.file_info.SectionAEntriesCount):
                file_metrics_entry = self._clean_value(PrefetchFileMetricsEntry.parse_stream(stream))
                if hasattr(file_metrics_entry, 'FileReference'):
                    file_metrics_entry.FileReference = self._clean_value(file_metrics_entry.FileReference)
                file_metrics.append(file_metrics_entry)
            return self._clean_value(file_metrics)
        finally:
            stream.seek(original_position)
    def _parse_file_info(self, stream=None):
        '''
        Args:
            stream: TextIOWrapper|BytesIO   => stream to read from
        Returns:
            Container<String, Any>
            Prefetch file information (see src.structures.prefetch.PrefetchFileInformation*)
        Preconditions:
            stream is of type TextIOWrapper or BytesIO  (assumed True)
        '''
        if self.header.Version == 'XP':
            PrefetchFileInformation = pfstructs.PrefetchFileInformation17
        elif self.header.Version == 'SEVEN':
            PrefetchFileInformation = pfstructs.PrefetchFileInformation23
        elif self.header.Version == 'EIGHT':
            PrefetchFileInformation = pfstructs.PrefetchFileInformation26
        else:
            PrefetchFileInformation = pfstructs.PrefetchFileInformation30
        file_info =  PrefetchFileInformation.parse_stream(stream)
        file_info.LastExecutionTime = list(map(
            lambda ft: WindowsTime.parse_filetime(ft), 
            file_info.RawLastExecutionTime
        ))
        return self._clean_value(file_info)
    def _parse_header(self, stream=None):
        '''
        Args:
            stream: TextIOWrapper|BytesIO   => stream to read from
        Returns:
            Container<String, Any>
            Prefetch file header information (see src.structures.prefetch.PrefetchHeader)
        Preconditions:
            stream is of type TextIOWrapper or BytesIO  (assumed True)
        '''
        header = pfstructs.PrefetchHeader.parse_stream(stream)
        header.Signature = header.RawSignature.decode('utf8')
        header.ExecutableName = header.RawExecutableName.split('\x00')[0]
        header.PrefetchHash = hex(header.RawPrefetchHash).replace('0x', '').upper()
        return self._clean_value(header)
    def __get_version(self):
        '''
        Args:
            N/A
        Returns:
            ByteString
            Prefetch version if successful, None otherwise
        Preconditions:
            N/A
        '''
        with open(self.source, 'rb') as pf:
            try:
                version = pfstructs.PrefetchVersion.parse_stream(pf)
            except:
                version = None
        return version
    def create_stream(self, persist=False):
        '''
        @FileParser.create_stream
        '''
        assert isinstance(persist, bool)
        if self.__get_version() is None:
            stream = BytesIO(DecompressWin10.decompress(self.source))
            if persist:
                self.stream = stream
            return stream
        return super().create_stream(persist)
