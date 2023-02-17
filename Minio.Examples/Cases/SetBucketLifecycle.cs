/*
 * MinIO .NET Library for Amazon S3 Compatible Cloud Storage, (C) 2021 MinIO, Inc.
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

using Minio.DataModel.ILM;

namespace Minio.Examples.Cases;

public class SetBucketLifecycle
{
    // Set Lifecycle configuration to the bucket
    public static async Task Run(IMinioClient minio,
        string bucketName = "my-bucket-name",
        LifecycleConfiguration lfc = null)
    {
        try
        {
            Console.WriteLine("Running example for API: SetBucketLifecycle");
            await minio.SetBucketLifecycleAsync(
                new SetBucketLifecycleArgs()
                    .WithBucket(bucketName)
                    .WithLifecycleConfiguration(lfc)
            ).ConfigureAwait(false);
            Console.WriteLine($"Bucket Lifecycle set for bucket {bucketName}.");
            Console.WriteLine();
        }
        catch (Exception e)
        {
            Console.WriteLine($"[Bucket]  Exception: {e}");
        }
    }
}