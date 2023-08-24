﻿/*
 * MinIO .NET Library for Amazon S3 Compatible Cloud Storage, (C) 2017 MinIO, Inc.
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

using Minio.DataModel.Result;

namespace Minio.Exceptions;

[Serializable]
public class InvalidBucketNameException : MinioException
{
    private readonly string bucketName;

    public InvalidBucketNameException(string bucketName, string message) : base(message)
    {
        this.bucketName = bucketName;
    }

    public InvalidBucketNameException(ResponseResult serverResponse) : base(serverResponse)
    {
    }

    public InvalidBucketNameException(string message) : base(message)
    {
    }

    public InvalidBucketNameException(string message, ResponseResult serverResponse) : base(message, serverResponse)
    {
    }

    public InvalidBucketNameException()
    {
    }

    public InvalidBucketNameException(string message, Exception innerException) : base(message, innerException)
    {
    }

    public override string ToString()
    {
        return $"{bucketName}: {base.ToString()}";
    }

    protected InvalidBucketNameException(System.Runtime.Serialization.SerializationInfo serializationInfo, System.Runtime.Serialization.StreamingContext streamingContext) : base(serializationInfo, streamingContext)
    {
    }
}
