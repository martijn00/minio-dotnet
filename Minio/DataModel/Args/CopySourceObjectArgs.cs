﻿/*
 * MinIO .NET Library for Amazon S3 Compatible Cloud Storage, (C) 2020, 2021 MinIO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Minio.DataModel.Args;

public class CopySourceObjectArgs : ObjectConditionalQueryArgs<CopySourceObjectArgs>
{
    public CopySourceObjectArgs()
    {
        RequestMethod = HttpMethod.Put;
        CopyOperationConditions = new CopyConditions();
        Headers = new Dictionary<string, string>(StringComparer.Ordinal);
    }

    internal string CopySourceObjectPath { get; set; }
    internal CopyConditions CopyOperationConditions { get; set; }

    public CopySourceObjectArgs WithCopyConditions(CopyConditions cp)
    {
        CopyOperationConditions = cp is not null ? cp.Clone() : new CopyConditions();
        return this;
    }

    // internal override HttpRequestMessageBuilder BuildRequest(HttpRequestMessageBuilder requestMessageBuilder)
    // {
    //     return requestMessageBuilder;
    // }
}