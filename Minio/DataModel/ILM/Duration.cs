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

using Minio.Helper;
using System.Xml.Serialization;

namespace Minio.DataModel.ILM;

[Serializable]
public abstract class Duration
{
    protected Duration()
    {
        Date = null;
        Days = null;
    }

    protected Duration(DateTime date)
    {
        date = new DateTime(date.Year, date.Month, date.Day, 0, 0, 0);
        Date = Utils.To8601String(date);
    }

    protected Duration(double days)
    {
        Days = days;
    }

    [XmlElement(ElementName = "Date", IsNullable = true)]
    public string Date { get; set; }

    [XmlElement(ElementName = "Days", IsNullable = true)]
    public double? Days { get; set; }
}