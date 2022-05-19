USE [ExitModule]
GO

SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[CertificateExtensions](
    [ExtensionRequestId] [int] NOT NULL,
    [ExtensionName] [nvarchar](50) NULL,
    [ExtensionDisplayName] [nvarchar](50) NULL,
    [ExtensionValue] [nvarchar](max) NULL,
    [ExtensionFlags] [int] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
