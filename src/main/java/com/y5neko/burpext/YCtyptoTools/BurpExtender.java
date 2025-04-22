package com.y5neko.burpext.YCtyptoTools;

import burp.*;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.List;

import static com.y5neko.burpext.YCtyptoTools.Config.*;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {
    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    // 请求/响应表格模型，成员变量
    private DefaultTableModel requestTableModel;
    private DefaultTableModel responseTableModel;

    // ============= UI ==============
    // 标签页面板
    private JTabbedPane tabbedPane;
    // 主设置面板
    private JPanel mainPanel;
    // 加密设置面板
    private JPanel cryptoPanel;

    /**
     * 注册Burp扩展的回调方法。
     *
     * @param callbacks
     *                  <code>IBurpExtenderCallbacks</code> 对象
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        // 获取插件路径
        String jarPath = callbacks.getExtensionFilename();
        String path = jarPath.substring(0, jarPath.lastIndexOf("/"));

        // 设置插件名称和版本号
        callbacks.setExtensionName(extensionName + " v" + extensionVersion);

        // 获取普通输出流和错误输出流
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);

        // ================================ 输出插件信息 ================================

        stdout.println("Y Crypto Tools v" + extensionVersion);
        stdout.println("[Author: Y5neKO]");
        stdout.println("[GitHub: https://github.com/Y5neKO]\n");
        stdout.println("LOG:");

        // ================================ 注册监听器 ================================

        callbacks.registerHttpListener(this);

        // ================================ 初始化插件文件 ================================
        File configDir = new File(configDirPath);
        if (!configDir.exists()) {
            boolean created = configDir.mkdirs();
            if (created) {
                System.out.println("目录已创建: " + configDirPath);
            } else {
                stderr.println("目录创建失败: " + configDirPath);
            }
        } else {
            System.out.println("目录已存在: " + configDirPath);
        }

        File cryptoConfigFile = new File(cryptoConfigFilePath);
        if (!cryptoConfigFile.exists()) {
            try (InputStream in = getClass().getClassLoader().getResourceAsStream("cryptoConfig.yaml")) {
                if (in == null) {
                    JOptionPane.showMessageDialog(null, "未找到默认配置文件 cryptoConfig.yaml", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                // JDK 8兼容的读取方式
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                byte[] temp = new byte[1024];
                int bytesRead;
                while ((bytesRead = in.read(temp)) != -1) {
                    buffer.write(temp, 0, bytesRead);
                }
                // 写入目标配置文件
                Files.write(Paths.get(cryptoConfigFilePath), buffer.toByteArray());
            } catch (Exception e) {
                stderr.println("初始化配置文件失败: " + e.getMessage());
            }
        }

        // ================================ UI相关 ================================
        SwingUtilities.invokeLater(() -> {
            // 创建标签页面板
            tabbedPane = new JTabbedPane();
            // ==================================================================================================================
            // ================================================= 主设置面板相关 ===================================================
            // ==================================================================================================================
            mainPanel = new JPanel();
            mainPanel.setLayout(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            // 通用设置
            gbc.insets = new Insets(5, 5, 5, 5);  // 组件间距（上，左，下，右）
            gbc.fill = GridBagConstraints.HORIZONTAL; // 默认填充方式

            // ==================== 第一行：标题 ====================
            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.gridwidth = GridBagConstraints.REMAINDER;
            gbc.anchor = GridBagConstraints.CENTER;
            gbc.weightx = 1.0;
            JLabel titleLabel = new JLabel("YCryptoTools设置", SwingConstants.CENTER); // 文本也居中
            titleLabel.setFont(new Font("微软雅黑", Font.BOLD, 20));          // 可选样式
            mainPanel.add(titleLabel, gbc);

            // ==================== 第二行：选择生效的组件 ======================
            // ==================== Burp组件复选框行 ====================
            gbc.gridx = 0;
            gbc.gridy = 1;
            gbc.gridwidth = GridBagConstraints.REMAINDER; // 跨全部列
            gbc.anchor = GridBagConstraints.CENTER;       // 整体居中
            JPanel burpCheckboxPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
            burpCheckboxPanel.setBorder(BorderFactory.createTitledBorder("Burp Suite组件"));
            // 常见Burp组件列表
            String[] burpComponents = {
                    "是否启用插件", "Proxy", "Intruder", "Repeater",
                    "Scanner", "Logger"
            };
            // 创建纯文本复选框
            for (String component : burpComponents) {
                JCheckBox checkBox = new JCheckBox(component);
                if (component.equals("是否启用插件")) {
                    checkBox.setSelected(true);
                } else {
                    checkBox.setFocusPainted(false);
                }
                burpCheckboxPanel.add(checkBox);
            }

            mainPanel.add(burpCheckboxPanel, gbc);

            // ==================== 第三行：白名单域名/地址 ====================
            gbc.gridx = 0;
            gbc.gridy = 2;
            gbc.gridwidth = GridBagConstraints.REMAINDER;
            gbc.anchor = GridBagConstraints.CENTER;
            JPanel whiteListPanel = new JPanel(new BorderLayout()); // 改用 BorderLayout
            whiteListPanel.setBorder(BorderFactory.createTitledBorder("白名单域名/地址"));

            // 白名单文本域
            JTextArea whiteListArea = new JTextArea(5, 40);
            whiteListArea.setEditable(true);
            whiteListArea.setLineWrap(true);
            whiteListArea.setWrapStyleWord(true);
            whiteListArea.setToolTipText("每行一个域名或地址，支持通配符*");

            // 将文本域放入滚动面板
            JScrollPane scrollPane = new JScrollPane(whiteListArea);
            scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS); // 确保垂直滚动条始终存在

            whiteListPanel.add(scrollPane, BorderLayout.CENTER); // 滚动面板填满白名单区域

            mainPanel.add(whiteListPanel, gbc);

            // ==================== 第四行：指定请求处理位置和参数数据类型 ====================
            gbc.gridx = 0;
            gbc.gridy = 3;
            gbc.gridwidth = GridBagConstraints.REMAINDER; // 跨全部列
            gbc.anchor = GridBagConstraints.CENTER;       // 整体居中


            // 创建子面板承载第二行的所有元素
            JPanel row2Panel = new JPanel();
            row2Panel.setLayout(new FlowLayout(FlowLayout.CENTER, 10, 0)); // 水平居中，间距10px

            // 添加元素到子面板
            row2Panel.add(new JLabel("指定请求处理位置："));
            String[] requestLocationItems = { "不处理", "请求体", "GET参数", "POST参数", "GET和POST参数", "自定义占位符（在做了在做了）" };
            JComboBox<String> requestLocationComboBox = new JComboBox<>(requestLocationItems);
            row2Panel.add(requestLocationComboBox);
            
            // 请求体加密顺序
            row2Panel.add(Box.createHorizontalStrut(20));
            row2Panel.add(new JLabel("请求体加密顺序："));
            JTextField requestCryptoOrderField = new JTextField(20);
            requestCryptoOrderField.setToolTipText("按顺序输入加解密器，以英文逗号分隔，如：\nAES1,DES1,AES2");
            row2Panel.add(requestCryptoOrderField);

            row2Panel.add(Box.createHorizontalStrut(20)); // 增加间距
            row2Panel.add(new JLabel("参数数据类型："));
            String[] requestParamItems = { "x-www-form-urlencoded", "JSON" };
            JComboBox<String> requestParamComboBox = new JComboBox<>(requestParamItems);
            row2Panel.add(requestParamComboBox);

            row2Panel.add(Box.createHorizontalStrut(20));
            row2Panel.add(new JLabel("指定响应处理位置："));
            String[] responseItems = { "不处理", "响应体", "JSON格式参数" };
            JComboBox<String> responseLocationComboBox = new JComboBox<>(responseItems);
            row2Panel.add(responseLocationComboBox);

            // 将子面板添加到主面板
            mainPanel.add(row2Panel, gbc);

            // ==================== 第五行：请求处理按钮和表格 ====================
            gbc.gridx = 0;
            gbc.gridy = 4;
            gbc.gridwidth = 1;
            gbc.fill = GridBagConstraints.VERTICAL;
            gbc.anchor = GridBagConstraints.CENTER;
            gbc.weightx = 0.0;
            gbc.weighty = 0.5;

            // 请求操作按钮面板（已正确命名）
            JPanel requestButtonPanel = new JPanel();
            requestButtonPanel.setLayout(new BoxLayout(requestButtonPanel, BoxLayout.Y_AXIS));
            requestButtonPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 30));

            // 创建按钮（添加request前缀）
            JButton requestAddButton = new JButton("添加");
            JButton requestEditButton = new JButton("编辑");
            JButton requestDeleteButton = new JButton("删除");
            JButton requestClearButton = new JButton("清空");

            // 统一按钮样式（更新变量名）
            for (JButton btn : Arrays.asList(requestAddButton, requestEditButton, requestDeleteButton, requestClearButton)) {
                btn.setAlignmentX(Component.CENTER_ALIGNMENT);
                btn.setMargin(new Insets(8, 20, 8, 20));
                btn.setFocusPainted(false);
            }

            // 垂直排列按钮（变量名已更新）
            requestButtonPanel.add(Box.createVerticalGlue());
            requestButtonPanel.add(requestAddButton);
            requestButtonPanel.add(Box.createVerticalStrut(15));
            requestButtonPanel.add(requestEditButton);
            requestButtonPanel.add(Box.createVerticalStrut(15));
            requestButtonPanel.add(requestDeleteButton);
            requestButtonPanel.add(Box.createVerticalStrut(15));
            requestButtonPanel.add(requestClearButton);
            requestButtonPanel.add(Box.createVerticalGlue());

            mainPanel.add(requestButtonPanel, gbc);

            // 请求参数表格区域（添加request前缀）
            gbc.gridx = 1;
            gbc.gridy = 4;
            gbc.gridwidth = GridBagConstraints.REMAINDER;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.weightx = 1.0;
            gbc.weighty = 0.5;

            // 表格模型（已正确命名）
            requestTableModel = new DefaultTableModel(
                    new Object[]{"参数名称", "GET/POST", "加解密器名称", "配置文件路径", "备注"}, 0) {
                @Override
                public boolean isCellEditable(int row, int column) {
                    return false;
                }
            };

            // 表格组件（添加request前缀）
            JTable requestTable = new JTable(requestTableModel);
            JScrollPane requestScrollPane = new JScrollPane(requestTable);
            requestScrollPane.setPreferredSize(new Dimension(800, 250));
            requestScrollPane.setBorder(BorderFactory.createTitledBorder("请求参数处理规则"));

            // 列模型（添加request前缀）
            TableColumnModel requestColumnModel = requestTable.getColumnModel();
            requestColumnModel.getColumn(0).setPreferredWidth(150);
            requestColumnModel.getColumn(1).setPreferredWidth(150);
            requestColumnModel.getColumn(2).setPreferredWidth(250);
            requestColumnModel.getColumn(3).setPreferredWidth(250);
            requestColumnModel.getColumn(4).setPreferredWidth(200);

            // 自动调整监听器（使用新变量名）
            requestScrollPane.addComponentListener(new ComponentAdapter() {
                @Override
                public void componentResized(ComponentEvent e) {
                    int totalWidth = requestScrollPane.getWidth() - 30;
                    requestColumnModel.getColumn(0).setPreferredWidth((int)(totalWidth * 0.15));
                    requestColumnModel.getColumn(1).setPreferredWidth((int)(totalWidth * 0.15));
                    requestColumnModel.getColumn(2).setPreferredWidth((int)(totalWidth * 0.25));
                    requestColumnModel.getColumn(3).setPreferredWidth((int)(totalWidth * 0.25));
                    requestColumnModel.getColumn(4).setPreferredWidth((int)(totalWidth * 0.20));
                }
            });

            mainPanel.add(requestScrollPane, gbc);

            // ==================== 第六行：响应处理按钮和表格 ====================
            // 响应按钮面板布局
            gbc.gridx = 0;
            gbc.gridy = 5;
            gbc.gridwidth = 1;
            gbc.fill = GridBagConstraints.VERTICAL;
            gbc.anchor = GridBagConstraints.CENTER;
            gbc.weightx = 0.0;
            gbc.weighty = 0.5;

            // 响应操作按钮面板
            JPanel responseButtonPanel = new JPanel();
            responseButtonPanel.setLayout(new BoxLayout(responseButtonPanel, BoxLayout.Y_AXIS));
            responseButtonPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 30));

            // 创建响应按钮（比请求少一个加密类型）
            JButton responseAddButton = new JButton("添加");
            JButton responseEditButton = new JButton("编辑");
            JButton responseDeleteButton = new JButton("删除");
            JButton responseClearButton = new JButton("清空");

            // 统一按钮样式
            for (JButton btn : Arrays.asList(responseAddButton, responseEditButton, responseDeleteButton, responseClearButton)) {
                btn.setAlignmentX(Component.CENTER_ALIGNMENT);
                btn.setMargin(new Insets(8, 20, 8, 20));
                btn.setFocusPainted(false);
            }

            // 垂直排列按钮
            responseButtonPanel.add(Box.createVerticalGlue());
            responseButtonPanel.add(responseAddButton);
            responseButtonPanel.add(Box.createVerticalStrut(15));
            responseButtonPanel.add(responseEditButton);
            responseButtonPanel.add(Box.createVerticalStrut(15));
            responseButtonPanel.add(responseDeleteButton);
            responseButtonPanel.add(Box.createVerticalStrut(15));
            responseButtonPanel.add(responseClearButton);
            responseButtonPanel.add(Box.createVerticalGlue());

            mainPanel.add(responseButtonPanel, gbc);

            // 响应参数表格区域
            gbc.gridx = 1;
            gbc.gridy = 5; // 第5行
            gbc.gridwidth = GridBagConstraints.REMAINDER;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.weightx = 1.0;
            gbc.weighty = 0.5;

            // 响应表格模型（四列：参数名称、加解密器名称、配置文件路径、备注）
            responseTableModel = new DefaultTableModel(
                    new Object[]{"参数名称", "加解密器名称", "配置文件路径", "备注"}, 0) {
                @Override
                public boolean isCellEditable(int row, int column) {
                    return false;
                }
            };

            JTable responseTable = new JTable(responseTableModel);
            JScrollPane responseScrollPane = new JScrollPane(responseTable);
            responseScrollPane.setPreferredSize(new Dimension(800, 200));
            responseScrollPane.setBorder(BorderFactory.createTitledBorder("响应参数处理规则"));

            // 列宽配置（比例：3:4:3:2）
            TableColumnModel responseColumnModel = responseTable.getColumnModel();
            responseColumnModel.getColumn(0).setPreferredWidth(240); // 30%
            responseColumnModel.getColumn(1).setPreferredWidth(320); // 40%
            responseColumnModel.getColumn(2).setPreferredWidth(240); // 30%
            responseColumnModel.getColumn(3).setPreferredWidth(160); // 20%

            // 自动调整列宽监听
            responseScrollPane.addComponentListener(new ComponentAdapter() {
                @Override
                public void componentResized(ComponentEvent e) {
                    int totalWidth = responseScrollPane.getWidth() - 30;
                    responseColumnModel.getColumn(0).setPreferredWidth((int)(totalWidth * 0.30));
                    responseColumnModel.getColumn(1).setPreferredWidth((int)(totalWidth * 0.40));
                    responseColumnModel.getColumn(2).setPreferredWidth((int)(totalWidth * 0.30));
                    responseColumnModel.getColumn(3).setPreferredWidth((int)(totalWidth * 0.20));
                }
            });

            mainPanel.add(responseScrollPane, gbc);

            // ==================== 第七行：保存配置按钮 ====================
            gbc.gridx = 0;
            gbc.gridy = 6; // 第7行
            gbc.gridwidth = GridBagConstraints.REMAINDER;
            gbc.fill = GridBagConstraints.NONE;
            gbc.anchor = GridBagConstraints.CENTER;
            gbc.weightx = 0.0;
            gbc.weighty = 0.0;

            JPanel configSavePanel = new JPanel();
            JButton configSaveButton = new JButton("保存配置");
            configSaveButton.setFont(new Font("微软雅黑", Font.BOLD, 14));
            configSaveButton.setPreferredSize(new Dimension(120, 35));

            JButton configCancelButton = new JButton("取消");
            configCancelButton.setFont(new Font("微软雅黑", Font.BOLD, 14));
            configCancelButton.setPreferredSize(new Dimension(120, 35));

            configSavePanel.add(configSaveButton);
            configSavePanel.add(configCancelButton);

            mainPanel.add(configSavePanel, gbc);
            // =======================================================================================================
            // ================================================= 主设置面板事件处理 =============================================
            // =======================================================================================================
            // 请求添加按钮事件处理
            requestAddButton.addActionListener(e -> {
                // 创建自定义对话框
                JDialog requestAddDialog = new JDialog((Frame) null, "添加参数处理规则", true);
                requestAddDialog.setLayout(new BorderLayout(10, 10));
                requestAddDialog.setMinimumSize(new Dimension(500, 350));
                // 错误提示面板
                JLabel requestAddDlgErrorLabel = new JLabel(" ");
                requestAddDlgErrorLabel.setForeground(Color.RED);
                requestAddDlgErrorLabel.setHorizontalAlignment(SwingConstants.CENTER);
                requestAddDlgErrorLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));

                // 主输入面板
                JPanel requestAddDlgMainPanel = new JPanel(new GridLayout(5, 2, 10, 15));
                requestAddDlgMainPanel.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));

                // 参数名称
                JTextField requestAddDlgParamNameField = new JTextField();
                JLabel requestAddDlgParamNameLabel = new JLabel("参数名称*：");
                requestAddDlgMainPanel.add(requestAddDlgParamNameLabel);
                requestAddDlgMainPanel.add(requestAddDlgParamNameField);

                // 参数类型
                JComboBox<String> requestAddDlgParamTypeCombo = new JComboBox<>(new String[]{"GET", "POST"});
                JLabel requestAddDlgParamTypeLabel = new JLabel("参数类型*：");
                requestAddDlgMainPanel.add(requestAddDlgParamTypeLabel);
                requestAddDlgMainPanel.add(requestAddDlgParamTypeCombo);

                // 加解密器名称
                JTextField requestAddDlgCryptoNameField = new JTextField();
                JLabel requestAddDlgCryptoNameLabel = new JLabel("加解密器名称*：");
                requestAddDlgMainPanel.add(requestAddDlgCryptoNameLabel);
                requestAddDlgMainPanel.add(requestAddDlgCryptoNameField);

                // 配置文件路径
                JPanel requestAddDlgConfigPathPanel = new JPanel(new BorderLayout(5, 0));
                JTextField requestAddDlgConfigPathField = new JTextField();
                JButton requestAddDlgBrowseButton = new JButton("浏览...");
                JLabel requestAddDlgConfigPathLabel = new JLabel("配置文件路径：");
                requestAddDlgConfigPathField.setToolTipText("不填写则使用默认配置");
                requestAddDlgConfigPathPanel.add(requestAddDlgConfigPathField, BorderLayout.CENTER);
                requestAddDlgConfigPathPanel.add(requestAddDlgBrowseButton, BorderLayout.EAST);
                requestAddDlgMainPanel.add(requestAddDlgConfigPathLabel);
                requestAddDlgMainPanel.add(requestAddDlgConfigPathPanel);

                // 备注
                JTextField requestAddDlgRemarkField = new JTextField();
                JLabel requestAddDlgRemarkLabel = new JLabel("备注：");
                requestAddDlgMainPanel.add(requestAddDlgRemarkLabel);
                requestAddDlgMainPanel.add(requestAddDlgRemarkField);

                // 文件选择逻辑
                requestAddDlgBrowseButton.addActionListener(ev -> {
                    JFileChooser requestAddDlgFileChooser = new JFileChooser();
                    requestAddDlgFileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                    int result = requestAddDlgFileChooser.showOpenDialog(requestAddDialog);
                    if (result == JFileChooser.APPROVE_OPTION) {
                        requestAddDlgConfigPathField.setText(
                                requestAddDlgFileChooser.getSelectedFile().getAbsolutePath()
                        );
                    }
                });

                // 按钮面板
                JPanel requestAddDlgButtonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 10));
                JButton requestAddDlgConfirmButton = new JButton("确认添加");
                JButton requestAddDlgCancelButton = new JButton("取消");
                requestAddDlgButtonPanel.add(requestAddDlgConfirmButton);
                requestAddDlgButtonPanel.add(requestAddDlgCancelButton);

                // 确认按钮逻辑
                requestAddDlgConfirmButton.addActionListener(ev -> {
                    StringBuilder errorMessage = new StringBuilder("输入错误");
                    boolean hasError = false;

                    // 参数名称验证
                    String paramName = requestAddDlgParamNameField.getText().trim();
                    if (paramName.isEmpty()) {
                        errorMessage.append(" | 参数名称不能为空");
                        requestAddDlgParamNameField.setBorder(BorderFactory.createLineBorder(Color.RED));
                        hasError = true;
                    } else {
                        // 检查重复（新增部分）
                        for (int i = 0; i < requestTableModel.getRowCount(); i++) {
                            if (paramName.equals(requestTableModel.getValueAt(i, 0))) {
                                errorMessage.append(" | 参数名称已存在");
                                requestAddDlgParamNameField.setBorder(BorderFactory.createLineBorder(Color.RED));
                                hasError = true;
                                break;
                            }
                        }
                    }

                    // 参数名称验证
                    if (requestAddDlgParamNameField.getText().trim().isEmpty()) {
                        errorMessage.append(" | 参数名称不能为空");
                        requestAddDlgParamNameField.setBorder(BorderFactory.createLineBorder(Color.RED));
                        hasError = true;
                    } else {
                        requestAddDlgParamNameField.setBorder(UIManager.getBorder("TextField.border"));
                    }

                    // 加解密器名称验证
                    if (requestAddDlgCryptoNameField.getText().trim().isEmpty()) {
                        errorMessage.append(" | 加解密器名称不能为空");
                        requestAddDlgCryptoNameField.setBorder(BorderFactory.createLineBorder(Color.RED));
                        hasError = true;
                    } else {
                        requestAddDlgCryptoNameField.setBorder(UIManager.getBorder("TextField.border"));
                    }

                    // 配置文件验证（可选）
                    if (!requestAddDlgConfigPathField.getText().isEmpty()) {
                        File configFile = new File(requestAddDlgConfigPathField.getText());
                        if (!configFile.exists()) {
                            errorMessage.append(" | 配置文件不存在");
                            requestAddDlgConfigPathField.setBorder(BorderFactory.createLineBorder(Color.RED));
                            hasError = true;
                        } else {
                            requestAddDlgConfigPathField.setBorder(UIManager.getBorder("TextField.border"));
                        }
                    }

                    if (hasError) {
                        requestAddDlgErrorLabel.setText(errorMessage.toString().replaceFirst("<br>$", ""));
                    } else {
                        // 收集数据
                        Object[] rowData = new Object[]{
                                requestAddDlgParamNameField.getText().trim(),
                                requestAddDlgParamTypeCombo.getSelectedItem(),
                                requestAddDlgCryptoNameField.getText().trim(),
                                requestAddDlgConfigPathField.getText().trim(),
                                requestAddDlgRemarkField.getText().trim()
                        };

                        // 添加至表格
                        requestTableModel.addRow(rowData);

                        // 关闭对话框
                        requestAddDialog.dispose();
                    }
                });

                // 取消按钮逻辑
                requestAddDlgCancelButton.addActionListener(ev -> requestAddDialog.dispose());

                // 组装对话框
                requestAddDialog.add(requestAddDlgErrorLabel, BorderLayout.NORTH);
                requestAddDialog.add(requestAddDlgMainPanel, BorderLayout.CENTER);
                requestAddDialog.add(requestAddDlgButtonPanel, BorderLayout.SOUTH);

                // 显示设置
                requestAddDialog.pack();
                requestAddDialog.setLocationRelativeTo(mainPanel);
                requestAddDialog.setVisible(true);
            });

            // 请求编辑按钮事件处理
            requestEditButton.addActionListener(e -> {
                // 获取选中的行
                int selectedRow = requestTable.getSelectedRow();
                if (selectedRow == -1) {
                    JOptionPane.showMessageDialog(mainPanel, "请先选择要编辑的行",
                            "提示", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }

                // 创建编辑对话框
                JDialog requestEditDialog = new JDialog((Frame) null, "编辑参数规则", true);
                requestEditDialog.setLayout(new BorderLayout(10, 10));
                requestEditDialog.setMinimumSize(new Dimension(500, 350));

                // 错误提示标签
                JLabel requestEditDlgErrorLabel = new JLabel(" ");
                requestEditDlgErrorLabel.setForeground(Color.RED);
                requestEditDlgErrorLabel.setHorizontalAlignment(SwingConstants.CENTER);
                requestEditDlgErrorLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));

                // 主输入面板（与添加对话框布局一致）
                JPanel requestEditDlgMainPanel = new JPanel(new GridLayout(5, 2, 10, 15));
                requestEditDlgMainPanel.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));

                // 参数名称
                JTextField requestEditDlgParamNameField = new JTextField();
                requestEditDlgParamNameField.setText(requestTableModel.getValueAt(selectedRow, 0).toString());
                requestEditDlgMainPanel.add(new JLabel("参数名称*："));
                requestEditDlgMainPanel.add(requestEditDlgParamNameField);

                // 参数类型
                JComboBox<String> requestEditDlgParamTypeCombo = new JComboBox<>(new String[]{"GET", "POST"});
                requestEditDlgParamTypeCombo.setSelectedItem(requestTableModel.getValueAt(selectedRow, 1));
                requestEditDlgMainPanel.add(new JLabel("参数类型*："));
                requestEditDlgMainPanel.add(requestEditDlgParamTypeCombo);

                // 加解密器名称
                JTextField requestEditDlgCryptoNameField = new JTextField();
                requestEditDlgCryptoNameField.setText(requestTableModel.getValueAt(selectedRow, 2).toString());
                requestEditDlgMainPanel.add(new JLabel("加解密器名称*："));
                requestEditDlgMainPanel.add(requestEditDlgCryptoNameField);

                // 配置文件路径
                JPanel requestEditDlgConfigPathPanel = new JPanel(new BorderLayout(5, 0));
                JTextField requestEditDlgConfigPathField = new JTextField();
                JButton requestEditDlgBrowseButton = new JButton("浏览...");
                requestEditDlgConfigPathField.setText(requestTableModel.getValueAt(selectedRow, 3).toString());
                requestEditDlgConfigPathField.setToolTipText("不填写则使用默认配置");
                requestEditDlgConfigPathPanel.add(requestEditDlgConfigPathField, BorderLayout.CENTER);
                requestEditDlgConfigPathPanel.add(requestEditDlgBrowseButton, BorderLayout.EAST);
                requestEditDlgMainPanel.add(new JLabel("配置文件路径："));
                requestEditDlgMainPanel.add(requestEditDlgConfigPathPanel);

                // 备注
                JTextField requestEditDlgRemarkField = new JTextField();
                requestEditDlgRemarkField.setText(requestTableModel.getValueAt(selectedRow, 4).toString());
                requestEditDlgMainPanel.add(new JLabel("备注："));
                requestEditDlgMainPanel.add(requestEditDlgRemarkField);

                // 文件选择逻辑
                requestEditDlgBrowseButton.addActionListener(ev -> {
                    JFileChooser requestEditDlgFileChooser = new JFileChooser();
                    requestEditDlgFileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                    int result = requestEditDlgFileChooser.showOpenDialog(requestEditDialog);
                    if (result == JFileChooser.APPROVE_OPTION) {
                        requestEditDlgConfigPathField.setText(
                                requestEditDlgFileChooser.getSelectedFile().getAbsolutePath()
                        );
                    }
                });

                // 按钮面板
                JPanel requestEditDlgButtonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 10));
                JButton requestEditDlgConfirmButton = new JButton("保存修改");
                JButton requestEditDlgCancelButton = new JButton("取消");
                requestEditDlgButtonPanel.add(requestEditDlgConfirmButton);
                requestEditDlgButtonPanel.add(requestEditDlgCancelButton);

                // 确认按钮逻辑
                requestEditDlgConfirmButton.addActionListener(ev -> {
                    StringBuilder errorMessage = new StringBuilder("输入错误");
                    boolean hasError = false;
                    // 参数名称验证
                    String paramName = requestEditDlgParamNameField.getText().trim();
                    if (paramName.isEmpty()) {
                        errorMessage.append(" | 参数名称不能为空");
                        requestEditDlgParamNameField.setBorder(BorderFactory.createLineBorder(Color.RED));
                        hasError = true;
                    } else {
                        // 检查重复（排除当前行）
                        for (int i = 0; i < requestTableModel.getRowCount(); i++) {
                            if (i != selectedRow && paramName.equals(requestTableModel.getValueAt(i, 0))) {
                                errorMessage.append(" | 参数名称已存在");
                                requestEditDlgParamNameField.setBorder(BorderFactory.createLineBorder(Color.RED));
                                hasError = true;
                                break;
                            }
                        }
                    }

                    // 参数名称验证
                    if (requestEditDlgParamNameField.getText().trim().isEmpty()) {
                        errorMessage.append(" | 参数名称不能为空");
                        requestEditDlgParamNameField.setBorder(BorderFactory.createLineBorder(Color.RED));
                        hasError = true;
                    } else {
                        requestEditDlgParamNameField.setBorder(UIManager.getBorder("TextField.border"));
                    }

                    // 加解密器名称验证
                    if (requestEditDlgCryptoNameField.getText().trim().isEmpty()) {
                        errorMessage.append(" | 加解密器名称不能为空");
                        requestEditDlgCryptoNameField.setBorder(BorderFactory.createLineBorder(Color.RED));
                        hasError = true;
                    } else {
                        requestEditDlgCryptoNameField.setBorder(UIManager.getBorder("TextField.border"));
                    }

                    // 配置文件验证
                    if (!requestEditDlgConfigPathField.getText().isEmpty()) {
                        File configFile = new File(requestEditDlgConfigPathField.getText());
                        if (!configFile.exists()) {
                            errorMessage.append(" | 配置文件不存在");
                            requestEditDlgConfigPathField.setBorder(BorderFactory.createLineBorder(Color.RED));
                            hasError = true;
                        } else {
                            requestEditDlgConfigPathField.setBorder(UIManager.getBorder("TextField.border"));
                        }
                    }

                    if (hasError) {
                        requestEditDlgErrorLabel.setText(errorMessage.toString().replaceFirst("<br>$", ""));
                    } else {
                        // 更新表格数据
                        requestTableModel.setValueAt(requestEditDlgParamNameField.getText().trim(), selectedRow, 0);
                        requestTableModel.setValueAt(requestEditDlgParamTypeCombo.getSelectedItem(), selectedRow, 1);
                        requestTableModel.setValueAt(requestEditDlgCryptoNameField.getText().trim(), selectedRow, 2);
                        requestTableModel.setValueAt(requestEditDlgConfigPathField.getText().trim(), selectedRow, 3);
                        requestTableModel.setValueAt(requestEditDlgRemarkField.getText().trim(), selectedRow, 4);

                        // 关闭对话框
                        requestEditDialog.dispose();
                    }
                });

                // 取消按钮逻辑
                requestEditDlgCancelButton.addActionListener(ev -> requestEditDialog.dispose());

                // 组装对话框
                requestEditDialog.add(requestEditDlgErrorLabel, BorderLayout.NORTH);
                requestEditDialog.add(requestEditDlgMainPanel, BorderLayout.CENTER);
                requestEditDialog.add(requestEditDlgButtonPanel, BorderLayout.SOUTH);

                // 显示设置
                requestEditDialog.pack();
                requestEditDialog.setLocationRelativeTo(mainPanel);
                requestEditDialog.setVisible(true);
            });

            // 删除按钮事件处理
            requestDeleteButton.addActionListener(e -> {
                // 获取选中的行（支持多选）
                int[] selectedRows = requestTable.getSelectedRows();

                if (selectedRows.length == 0) {
                    JOptionPane.showMessageDialog(mainPanel,
                            "请至少选择一行数据进行删除",
                            "提示",
                            JOptionPane.INFORMATION_MESSAGE);
                    return;
                }

                // 确认对话框
                int confirm = JOptionPane.showConfirmDialog(
                        mainPanel,
                        "确定要删除选中的 " + selectedRows.length + " 项数据吗？",
                        "确认删除",
                        JOptionPane.YES_NO_OPTION
                );

                if (confirm == JOptionPane.YES_OPTION) {
                    // 倒序删除避免索引变化
                    for (int i = selectedRows.length - 1; i >= 0; i--) {
                        requestTableModel.removeRow(selectedRows[i]);
                    }
                }
            });

            // 清空按钮事件处理
            requestClearButton.addActionListener(e -> {
                // 空数据检查
                if (requestTableModel.getRowCount() == 0) {
                    JOptionPane.showMessageDialog(mainPanel,
                            "表格中暂无数据可清空",
                            "提示",
                            JOptionPane.INFORMATION_MESSAGE);
                    return;
                }

                // 二次确认
                int confirm = JOptionPane.showConfirmDialog(
                        mainPanel,
                        "确定要清空所有数据吗？该操作不可恢复！",
                        "危险操作确认",
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.WARNING_MESSAGE
                );

                if (confirm == JOptionPane.YES_OPTION) {
                    requestTableModel.setRowCount(0);
                }
            });

            requestTable.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2) {
                        requestEditButton.doClick();
                    }
                }
            });
            // ========================================== 响应按钮事件处理 =======================================
            responseAddButton.addActionListener(e -> {
                JDialog responseAddDialog = new JDialog((Frame) null, "添加响应参数规则", true);
                responseAddDialog.setLayout(new BorderLayout(10, 10));
                responseAddDialog.setMinimumSize(new Dimension(500, 300));

                // 错误提示标签
                JLabel responseAddDlgErrorLabel = new JLabel(" ");
                responseAddDlgErrorLabel.setForeground(Color.RED);
                responseAddDlgErrorLabel.setHorizontalAlignment(SwingConstants.CENTER);

                // 主输入面板（比请求少一列）
                JPanel responseAddDlgMainPanel = new JPanel(new GridLayout(4, 2, 10, 15));
                responseAddDlgMainPanel.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));

                // 参数名称
                JTextField paramNameField = new JTextField();
                responseAddDlgMainPanel.add(new JLabel("参数名称*："));
                responseAddDlgMainPanel.add(paramNameField);

                // 加解密器名称
                JTextField cryptoNameField = new JTextField();
                responseAddDlgMainPanel.add(new JLabel("加解密器名称*："));
                responseAddDlgMainPanel.add(cryptoNameField);

                // 配置文件路径
                JPanel configPathPanel = new JPanel(new BorderLayout());
                JTextField configPathField = new JTextField();
                JButton browseButton = new JButton("浏览...");
                configPathPanel.add(configPathField, BorderLayout.CENTER);
                configPathPanel.add(browseButton, BorderLayout.EAST);
                responseAddDlgMainPanel.add(new JLabel("配置文件路径："));
                responseAddDlgMainPanel.add(configPathPanel);

                // 备注
                JTextField remarkField = new JTextField();
                responseAddDlgMainPanel.add(new JLabel("备注："));
                responseAddDlgMainPanel.add(remarkField);

                // 文件选择
                browseButton.addActionListener(ev -> {
                    JFileChooser fileChooser = new JFileChooser();
                    if (fileChooser.showOpenDialog(responseAddDialog) == JFileChooser.APPROVE_OPTION) {
                        configPathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
                    }
                });

                // 按钮面板
                JPanel buttonPanel = new JPanel(new FlowLayout());
                JButton confirmButton = new JButton("确认");
                JButton cancelButton = new JButton("取消");

                confirmButton.addActionListener(ev -> {
                    // 验证逻辑（去掉了加密类型检查）
                    boolean hasError = false;
                    StringBuilder errorMsg = new StringBuilder();

                    if (paramNameField.getText().trim().isEmpty()) {
                        errorMsg.append("参数名称不能为空");
                        paramNameField.setBorder(BorderFactory.createLineBorder(Color.RED));
                        hasError = true;
                    }

                    if (cryptoNameField.getText().trim().isEmpty()) {
                        errorMsg.append(errorMsg.length()>0 ? " | " : "").append("加解密器名称不能为空");
                        cryptoNameField.setBorder(BorderFactory.createLineBorder(Color.RED));
                        hasError = true;
                    }

                    if (!configPathField.getText().isEmpty()) {
                        File configFile = new File(configPathField.getText());
                        if (!configFile.exists()) {
                            errorMsg.append(errorMsg.length()>0 ? " | " : "").append("配置文件不存在");
                            configPathField.setBorder(BorderFactory.createLineBorder(Color.RED));
                            hasError = true;
                        }
                    }

                    if (hasError) {
                        responseAddDlgErrorLabel.setText(errorMsg.toString());
                    } else {
                        // 添加数据到表格
                        responseTableModel.addRow(new Object[]{
                                paramNameField.getText().trim(),
                                cryptoNameField.getText().trim(),
                                configPathField.getText().trim(),
                                remarkField.getText().trim()
                        });
                        responseAddDialog.dispose();
                    }
                });

                cancelButton.addActionListener(ev -> responseAddDialog.dispose());

                buttonPanel.add(confirmButton);
                buttonPanel.add(cancelButton);

                // 组装对话框
                responseAddDialog.add(responseAddDlgErrorLabel, BorderLayout.NORTH);
                responseAddDialog.add(responseAddDlgMainPanel, BorderLayout.CENTER);
                responseAddDialog.add(buttonPanel, BorderLayout.SOUTH);

                responseAddDialog.pack();
                responseAddDialog.setLocationRelativeTo(mainPanel);
                responseAddDialog.setVisible(true);
            });
            // 响应编辑按钮事件处理
            responseEditButton.addActionListener(e -> {
                int selectedRow = responseTable.getSelectedRow();
                if (selectedRow == -1) {
                    JOptionPane.showMessageDialog(mainPanel, "请先选择要编辑的行", "提示", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
                // 创建编辑对话框
                JDialog editDialog = new JDialog((Frame) null, "编辑响应规则", true);
                editDialog.setLayout(new BorderLayout(10, 10));
                editDialog.setMinimumSize(new Dimension(500, 300));
                // 错误提示标签
                JLabel errorLabel = new JLabel(" ");
                errorLabel.setForeground(Color.RED);
                errorLabel.setHorizontalAlignment(SwingConstants.CENTER);
                // 主输入面板
                JPanel mainInputPanel = new JPanel(new GridLayout(4, 2, 10, 15));
                mainInputPanel.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));
                // 初始化字段
                JTextField paramField = new JTextField(responseTableModel.getValueAt(selectedRow, 0).toString());
                JTextField cryptoField = new JTextField(responseTableModel.getValueAt(selectedRow, 1).toString());
                JTextField configField = new JTextField(responseTableModel.getValueAt(selectedRow, 2).toString());
                JTextField remarkField = new JTextField(responseTableModel.getValueAt(selectedRow, 3).toString());
                // 配置文件路径选择组件
                JPanel configPathPanel = new JPanel(new BorderLayout());
                JButton browseButton = new JButton("浏览...");
                configPathPanel.add(configField, BorderLayout.CENTER);
                configPathPanel.add(browseButton, BorderLayout.EAST);
                // 组装输入项
                mainInputPanel.add(new JLabel("参数名称*："));
                mainInputPanel.add(paramField);
                mainInputPanel.add(new JLabel("加解密器名称*："));
                mainInputPanel.add(cryptoField);
                mainInputPanel.add(new JLabel("配置文件路径："));
                mainInputPanel.add(configPathPanel);
                mainInputPanel.add(new JLabel("备注："));
                mainInputPanel.add(remarkField);
                // 文件选择逻辑
                browseButton.addActionListener(ev -> {
                    JFileChooser fileChooser = new JFileChooser();
                    if (fileChooser.showOpenDialog(editDialog) == JFileChooser.APPROVE_OPTION) {
                        configField.setText(fileChooser.getSelectedFile().getAbsolutePath());
                    }
                });
                // 按钮面板
                JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
                JButton confirmBtn = new JButton("保存");
                JButton cancelBtn = new JButton("取消");
                confirmBtn.addActionListener(ev -> {
                    // 验证逻辑
                    boolean hasError = false;
                    StringBuilder errorMsg = new StringBuilder();
                    // 重置边框颜色
                    paramField.setBorder(UIManager.getBorder("TextField.border"));
                    cryptoField.setBorder(UIManager.getBorder("TextField.border"));
                    configField.setBorder(UIManager.getBorder("TextField.border"));
                    if (paramField.getText().trim().isEmpty()) {
                        errorMsg.append("参数名称不能为空");
                        paramField.setBorder(BorderFactory.createLineBorder(Color.RED));
                        hasError = true;
                    }
                    if (cryptoField.getText().trim().isEmpty()) {
                        errorMsg.append(errorMsg.length()>0 ? " | " : "").append("加解密器名称不能为空");
                        cryptoField.setBorder(BorderFactory.createLineBorder(Color.RED));
                        hasError = true;
                    }
                    if (!configField.getText().isEmpty()) {
                        File configFile = new File(configField.getText());
                        if (!configFile.exists()) {
                            errorMsg.append(errorMsg.length()>0 ? " | " : "").append("配置文件不存在");
                            configField.setBorder(BorderFactory.createLineBorder(Color.RED));
                            hasError = true;
                        }
                    }
                    if (hasError) {
                        errorLabel.setText(errorMsg.toString());
                    } else {
                        // 更新表格数据
                        responseTableModel.setValueAt(paramField.getText().trim(), selectedRow, 0);
                        responseTableModel.setValueAt(cryptoField.getText().trim(), selectedRow, 1);
                        responseTableModel.setValueAt(configField.getText().trim(), selectedRow, 2);
                        responseTableModel.setValueAt(remarkField.getText().trim(), selectedRow, 3);
                        editDialog.dispose();
                    }
                });
                cancelBtn.addActionListener(ev -> editDialog.dispose());
                buttonPanel.add(confirmBtn);
                buttonPanel.add(cancelBtn);
                // 组装对话框
                editDialog.add(errorLabel, BorderLayout.NORTH);
                editDialog.add(mainInputPanel, BorderLayout.CENTER);
                editDialog.add(buttonPanel, BorderLayout.SOUTH);
                editDialog.pack();
                editDialog.setLocationRelativeTo(mainPanel);
                editDialog.setVisible(true);
            });
            // 响应删除按钮
            responseDeleteButton.addActionListener(e -> {
                int[] selectedRows = responseTable.getSelectedRows();
                if (selectedRows.length == 0) {
                    JOptionPane.showMessageDialog(mainPanel, "请至少选择一行进行删除", "提示", JOptionPane.WARNING_MESSAGE);
                    return;
                }

                int confirm = JOptionPane.showConfirmDialog(
                        mainPanel,
                        "确定要删除选中的 " + selectedRows.length + " 条规则吗？",
                        "确认删除",
                        JOptionPane.YES_NO_OPTION
                );

                if (confirm == JOptionPane.YES_OPTION) {
                    // 从后往前删除避免索引错位
                    for (int i = selectedRows.length - 1; i >= 0; i--) {
                        responseTableModel.removeRow(selectedRows[i]);
                    }
                }
            });
            // 响应清空按钮
            responseClearButton.addActionListener(e -> {
                if (responseTableModel.getRowCount() == 0) {
                    JOptionPane.showMessageDialog(mainPanel, "表格已为空", "提示", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }

                int confirm = JOptionPane.showConfirmDialog(
                        mainPanel,
                        "确定要清空全部 " + responseTableModel.getRowCount() + " 条规则吗？",
                        "确认清空",
                        JOptionPane.YES_NO_OPTION
                );

                if (confirm == JOptionPane.YES_OPTION) {
                    responseTableModel.setRowCount(0);
                }
            });
            // 表格双击事件（与请求表格相同）
            responseTable.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2) {
                        responseEditButton.doClick();
                    }
                }
            });
            // ========================= 配置保存按钮事件处理 =========================
            configSaveButton.addActionListener(e -> {
                try {
                    JSONObject YCryptoConfig = new JSONObject();

                    // 1. 收集启用的Burp组件
                    JSONArray enabledComponents = new JSONArray();
                    Component[] burpCheckboxes = burpCheckboxPanel.getComponents();
                    for (Component comp : burpCheckboxes) {
                        if (comp instanceof JCheckBox) {
                            JCheckBox cb = (JCheckBox) comp;
                            if (cb.isSelected()) {
                                enabledComponents.add(cb.getText());
                            }
                        }
                    }
                    YCryptoConfig.put("enabledComponents", enabledComponents);
                    // 2. 收集下拉框设置
                    YCryptoConfig.put("requestLocation", requestLocationComboBox.getSelectedItem());
                    YCryptoConfig.put("paramType", requestParamComboBox.getSelectedItem());
                    YCryptoConfig.put("requestCryptoOrder", requestCryptoOrderField.getText());
                    YCryptoConfig.put("responseLocation", responseLocationComboBox.getSelectedItem());
                    // 3. 收集请求规则
                    JSONArray requestRules = new JSONArray();
                    for (int i = 0; i < requestTableModel.getRowCount(); i++) {
                        JSONObject rule = new JSONObject();
                        rule.put("paramName", requestTableModel.getValueAt(i, 0));
                        rule.put("paramType", requestTableModel.getValueAt(i, 1));
                        rule.put("cryptoName", requestTableModel.getValueAt(i, 2));
                        rule.put("configPath", requestTableModel.getValueAt(i, 3));
                        rule.put("remark", requestTableModel.getValueAt(i, 4));
                        requestRules.add(rule);
                    }
                    YCryptoConfig.put("requestRules", requestRules);
                    // 4. 收集响应规则
                    JSONArray responseRules = new JSONArray();
                    for (int i = 0; i < responseTableModel.getRowCount(); i++) {
                        JSONObject rule = new JSONObject();
                        rule.put("paramName", responseTableModel.getValueAt(i, 0));
                        rule.put("cryptoName", responseTableModel.getValueAt(i, 1));
                        rule.put("configPath", responseTableModel.getValueAt(i, 2));
                        rule.put("remark", responseTableModel.getValueAt(i, 3));
                        responseRules.add(rule);
                    }
                    YCryptoConfig.put("responseRules", responseRules);
                    // 5. 收集白名单设置
                    YCryptoConfig.put("whitelist", whiteListArea.getText());
                    // 保存到文件
                    File file = new File(configDirPath + "YCryptoConfig.json");
                    if (!file.getName().toLowerCase().endsWith(".json")) {
                        file = new File(file.getParentFile(), file.getName() + ".json");
                    }
                    String jsonString = JSON.toJSONString(YCryptoConfig, JSONWriter.Feature.PrettyFormat);
                    jsonString = jsonString.replace("\r\n", "\n").replace("\r", "\n");
                    OutputStreamWriter writer = null;
                    try {
                        writer = new OutputStreamWriter(Files.newOutputStream(file.toPath()), StandardCharsets.UTF_8);
                        writer.write(jsonString);
                        writer.flush();
                        JOptionPane.showMessageDialog(mainPanel,
                                "配置保存成功！\n路径：" + file.getAbsolutePath(),
                                "保存成功",
                                JOptionPane.INFORMATION_MESSAGE);
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(mainPanel,
                                "保存失败：\n" + ex.getMessage(),
                                "错误",
                                JOptionPane.ERROR_MESSAGE);
                    } finally {
                        if (writer != null) try { writer.close(); } catch (IOException ignore) {}
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(mainPanel,
                            "未知错误：\n" + ex.getMessage(),
                            "错误",
                            JOptionPane.ERROR_MESSAGE);
                }
            });
            configCancelButton.addActionListener(e -> {
                File configFile = new File(configFilePath);
                if (configFile.exists()) {
                    BufferedReader reader = null;
                    StringBuilder sb = new StringBuilder();
                    try {
                        reader = new BufferedReader(new InputStreamReader(Files.newInputStream(configFile.toPath()), StandardCharsets.UTF_8));
                        String line;
                        while ((line = reader.readLine()) != null) {
                            sb.append(line).append("\n");
                        }
                        JSONObject settingConfig = JSON.parseObject(sb.toString());
                        // 1. 恢复 Burp 组件勾选状态
                        JSONArray enabledComponents = settingConfig.getJSONArray("enabledComponents");
                        Component[] checkboxes = burpCheckboxPanel.getComponents();
                        for (Component comp : checkboxes) {
                            if (comp instanceof JCheckBox) {
                                JCheckBox cb = (JCheckBox) comp;
                                cb.setSelected(enabledComponents.contains(cb.getText()));
                            }
                        }
                        // 2. 恢复下拉框选择
                        requestLocationComboBox.setSelectedItem(settingConfig.getString("requestLocation"));
                        requestParamComboBox.setSelectedItem(settingConfig.getString("paramType"));
                        requestCryptoOrderField.setText(settingConfig.getString("requestCryptoOrder"));
                        responseLocationComboBox.setSelectedItem(settingConfig.getString("responseLocation"));
                        // 3. 恢复请求规则表格
                        requestTableModel.setRowCount(0);
                        JSONArray requestRules = settingConfig.getJSONArray("requestRules");
                        for (int i = 0; i < requestRules.size(); i++) {
                            JSONObject rule = requestRules.getJSONObject(i);
                            requestTableModel.addRow(new Object[]{
                                    rule.getString("paramName"),
                                    rule.getString("paramType"),
                                    rule.getString("cryptoName"),
                                    rule.getString("configPath"),
                                    rule.getString("remark")
                            });
                        }
                        // 4. 恢复响应规则表格
                        responseTableModel.setRowCount(0);
                        JSONArray responseRules = settingConfig.getJSONArray("responseRules");
                        for (int i = 0; i < responseRules.size(); i++) {
                            JSONObject rule = responseRules.getJSONObject(i);
                            responseTableModel.addRow(new Object[]{
                                    rule.getString("paramName"),
                                    rule.getString("cryptoName"),
                                    rule.getString("configPath"),
                                    rule.getString("remark")
                            });
                        }
                        // 5. 恢复白名单设置
                        whiteListArea.setText(settingConfig.getString("whitelist"));

                        stdout.println("配置文件存在，加载成功");
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(mainPanel,
                                "加载失败：\n" + ex.getMessage(),
                                "错误",
                                JOptionPane.ERROR_MESSAGE);
                    } finally {
                        if (reader != null) try { reader.close(); } catch (IOException ignore) {}
                    }
                }
            });
            // ==================================== 加载配置文件 =========================================
            File configFile = new File(configFilePath);
            if (configFile.exists()) {
                BufferedReader reader = null;
                StringBuilder sb = new StringBuilder();
                try {
                    reader = new BufferedReader(new InputStreamReader(Files.newInputStream(configFile.toPath()), StandardCharsets.UTF_8));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                    JSONObject config = JSON.parseObject(sb.toString());
                    // 1. 恢复 Burp 组件勾选状态
                    JSONArray enabledComponents = config.getJSONArray("enabledComponents");
                    Component[] checkboxes = burpCheckboxPanel.getComponents();
                    for (Component comp : checkboxes) {
                        if (comp instanceof JCheckBox) {
                            JCheckBox cb = (JCheckBox) comp;
                            cb.setSelected(enabledComponents.contains(cb.getText()));
                        }
                    }
                    // 2. 恢复下拉框选择
                    requestLocationComboBox.setSelectedItem(config.getString("requestLocation"));
                    requestParamComboBox.setSelectedItem(config.getString("paramType"));
                    requestCryptoOrderField.setText(config.getString("requestCryptoOrder"));
                    responseLocationComboBox.setSelectedItem(config.getString("responseLocation"));
                    // 3. 恢复请求规则表格
                    requestTableModel.setRowCount(0);
                    JSONArray requestRules = config.getJSONArray("requestRules");
                    for (int i = 0; i < requestRules.size(); i++) {
                        JSONObject rule = requestRules.getJSONObject(i);
                        requestTableModel.addRow(new Object[]{
                                rule.getString("paramName"),
                                rule.getString("paramType"),
                                rule.getString("cryptoName"),
                                rule.getString("configPath"),
                                rule.getString("remark")
                        });
                    }
                    // 4. 恢复响应规则表格
                    responseTableModel.setRowCount(0);
                    JSONArray responseRules = config.getJSONArray("responseRules");
                    for (int i = 0; i < responseRules.size(); i++) {
                        JSONObject rule = responseRules.getJSONObject(i);
                        responseTableModel.addRow(new Object[]{
                                rule.getString("paramName"),
                                rule.getString("cryptoName"),
                                rule.getString("configPath"),
                                rule.getString("remark")
                        });
                    }
                    // 5. 恢复白名单设置
                    whiteListArea.setText(config.getString("whitelist"));
                    stdout.println("配置文件存在，加载成功");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(mainPanel,
                            "加载失败：\n" + ex.getMessage(),
                            "错误",
                            JOptionPane.ERROR_MESSAGE);
                } finally {
                    if (reader != null) try { reader.close(); } catch (IOException ignore) {}
                }
            }

            // ===================================================================================================================
            // ================================================= 加密设置面板相关 ===================================================
            // ===================================================================================================================
            String[] cryptoSettingColumns = {
                    "名称", "algorithm", "mode", "padding", "key", "keyFormat", "iv", "ivFormat", "privateKey", "publicKey"
            };
            cryptoPanel = new JPanel(new GridBagLayout());
            GridBagConstraints cryptoSettingGbc = new GridBagConstraints();
            // ===== 第一行：标题 =====
            JLabel cryptoSettingTitleLabel = new JLabel("加解密器配置");
            cryptoSettingTitleLabel.setFont(new Font("宋体", Font.BOLD, 24));
            cryptoSettingTitleLabel.setHorizontalAlignment(SwingConstants.CENTER);

            cryptoSettingGbc.gridx = 0;
            cryptoSettingGbc.gridy = 0;
            cryptoSettingGbc.gridwidth = 2;
            cryptoSettingGbc.fill = GridBagConstraints.HORIZONTAL;
            cryptoSettingGbc.insets = new Insets(10, 10, 10, 10);
            cryptoPanel.add(cryptoSettingTitleLabel, cryptoSettingGbc);

            // ===== 第二行：按钮区 + 表格 =====
            // 左侧按钮垂直面板
            JPanel ctyptoSettingButtonPanel = new JPanel();
            ctyptoSettingButtonPanel.setLayout(new BoxLayout(ctyptoSettingButtonPanel, BoxLayout.Y_AXIS));

            JButton ctyptoSettingAddButton = new JButton("添加");
            JButton ctyptoSettingEditButton = new JButton("编辑");
            JButton ctyptoSettingDeleteButton = new JButton("删除");
            JButton ctyptoSettingClearButton = new JButton("清空");
            ctyptoSettingButtonPanel.add(Box.createVerticalGlue());
            ctyptoSettingButtonPanel.add(ctyptoSettingAddButton);
            ctyptoSettingButtonPanel.add(Box.createVerticalStrut(15));
            ctyptoSettingButtonPanel.add(ctyptoSettingEditButton);
            ctyptoSettingButtonPanel.add(Box.createVerticalStrut(15));
            ctyptoSettingButtonPanel.add(ctyptoSettingDeleteButton);
            ctyptoSettingButtonPanel.add(Box.createVerticalStrut(15));
            ctyptoSettingButtonPanel.add(ctyptoSettingClearButton);
            ctyptoSettingButtonPanel.add(Box.createVerticalGlue());

            cryptoSettingGbc.gridx = 0;
            cryptoSettingGbc.gridy = 1;
            cryptoSettingGbc.gridwidth = 1;
            cryptoSettingGbc.weightx = 0;
            cryptoSettingGbc.weighty = 1;
            cryptoSettingGbc.fill = GridBagConstraints.VERTICAL;
            cryptoSettingGbc.anchor = GridBagConstraints.CENTER;
            cryptoPanel.add(ctyptoSettingButtonPanel, cryptoSettingGbc);
            // 右侧表格
            DefaultTableModel ctyptoSettingTableModel = new DefaultTableModel(cryptoSettingColumns, 0) {
                @Override
                public boolean isCellEditable(int row, int column) {
                    return false; // 禁止所有单元格编辑
                }
            };
            JTable ctyptoSettingtable = new JTable(ctyptoSettingTableModel);
            JScrollPane ctyptoSettingScrollPane = new JScrollPane(ctyptoSettingtable);

            cryptoSettingGbc.gridx = 1;
            cryptoSettingGbc.gridy = 1;
            cryptoSettingGbc.fill = GridBagConstraints.BOTH;
            cryptoSettingGbc.weightx = 1;
            cryptoSettingGbc.weighty = 1;
            cryptoPanel.add(ctyptoSettingScrollPane, cryptoSettingGbc);
            // ===== 第三行：底部按钮 =====
            JPanel ctyptoSettingBottomPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 10));
            JButton ctyptoSettingSaveButton = new JButton("保存配置");
            JButton ctyptoSettingResetButton = new JButton("恢复默认");
            ctyptoSettingBottomPanel.add(ctyptoSettingSaveButton);
            ctyptoSettingBottomPanel.add(ctyptoSettingResetButton);

            cryptoSettingGbc.gridx = 0;
            cryptoSettingGbc.gridy = 2;
            cryptoSettingGbc.gridwidth = 2;
            cryptoSettingGbc.weightx = 0;
            cryptoSettingGbc.weighty = 0;
            cryptoSettingGbc.fill = GridBagConstraints.HORIZONTAL;
            cryptoPanel.add(ctyptoSettingBottomPanel, cryptoSettingGbc);

            // ======================== 后续处理 =======================
            List<String> supportedAlgorithm = new ArrayList<>();
            Map<String, Map<String, String>> cryptoEngines = new LinkedHashMap<>();

            try {
                Yaml yaml = new Yaml();
                Map<String, Object> yamlData = yaml.load(Files.newInputStream(Paths.get(cryptoConfigFilePath)));

                // 读取 supportedAlgorithm
                supportedAlgorithm = (List<String>) yamlData.get("supportedAlgorithm");

                // 读取 cryptoEngines
                Map<String, Object> enginesRaw = (Map<String, Object>) yamlData.get("cryptoEngines");

                for (Map.Entry<String, Object> entry : enginesRaw.entrySet()) {
                    String name = entry.getKey();
                    Map<String, String> engineDetail = (Map<String, String>) entry.getValue();
                    cryptoEngines.put(name, engineDetail);
                }
            } catch (Exception e) {
                JOptionPane.showMessageDialog(null, "加载配置失败: " + e.getMessage());
            }
            // ====================================== 事件监听 ==========================================
            // 添加按钮事件
            List<String> finalSupportedAlgorithm = supportedAlgorithm;
            ctyptoSettingAddButton.addActionListener(e -> {
                while (true) {
                    JPanel inputPanel = new JPanel(new GridLayout(11, 2, 10, 5));

                    // 名称
                    inputPanel.add(new JLabel("名称："));
                    JTextField nameField = new JTextField();
                    inputPanel.add(nameField);

                    // algorithm
                    inputPanel.add(new JLabel("algorithm："));
                    JComboBox<String> algorithmCombo = new JComboBox<>(finalSupportedAlgorithm.toArray(new String[0]));
                    inputPanel.add(algorithmCombo);

                    // mode
                    inputPanel.add(new JLabel("mode："));
                    JComboBox<String> modeCombo = new JComboBox<>(new String[]{"", "ECB", "CBC", "CFB", "OFB", "CTR", "GCM"});
                    inputPanel.add(modeCombo);

                    // padding
                    inputPanel.add(new JLabel("padding："));
                    JComboBox<String> paddingCombo = new JComboBox<>(new String[]{"", "PKCS5Padding", "PKCS7Padding", "NoPadding", "ISO10126Padding"});
                    inputPanel.add(paddingCombo);

                    // key
                    inputPanel.add(new JLabel("key："));
                    JTextField keyField = new JTextField();
                    inputPanel.add(keyField);

                    // keyFormat
                    inputPanel.add(new JLabel("keyFormat："));
                    JComboBox<String> keyFormatCombo = new JComboBox<>(new String[]{"", "utf8", "base64", "hex"});
                    inputPanel.add(keyFormatCombo);

                    // iv
                    inputPanel.add(new JLabel("iv："));
                    JTextField ivField = new JTextField();
                    inputPanel.add(ivField);

                    // ivFormat
                    inputPanel.add(new JLabel("ivFormat："));
                    JComboBox<String> ivFormatCombo = new JComboBox<>(new String[]{"", "utf8", "base64", "hex"});
                    inputPanel.add(ivFormatCombo);

                    // privateKey
                    inputPanel.add(new JLabel("privateKey："));
                    JTextField privateKeyField = new JTextField();
                    inputPanel.add(privateKeyField);

                    // publicKey
                    inputPanel.add(new JLabel("publicKey："));
                    JTextField publicKeyField = new JTextField();
                    inputPanel.add(publicKeyField);

                    int result = JOptionPane.showConfirmDialog(null, inputPanel, "添加加解密器", JOptionPane.OK_CANCEL_OPTION);
                    if (result != JOptionPane.OK_OPTION) break;

                    String name = nameField.getText().trim();
                    if (name.isEmpty()) {
                        JOptionPane.showMessageDialog(null, "名称不能为空！");
                        continue;
                    }
                    if (cryptoEngines.containsKey(name)) {
                        JOptionPane.showMessageDialog(null, "名称已存在，请使用唯一名称！");
                        continue;
                    }

                    Map<String, String> config = new LinkedHashMap<>();
                    config.put("algorithm", (String) algorithmCombo.getSelectedItem());
                    config.put("mode", (String) modeCombo.getSelectedItem());
                    config.put("padding", (String) paddingCombo.getSelectedItem());
                    config.put("key", keyField.getText().trim());
                    config.put("keyFormat", (String) keyFormatCombo.getSelectedItem());
                    config.put("iv", ivField.getText().trim());
                    config.put("ivFormat", (String) ivFormatCombo.getSelectedItem());
                    config.put("privateKey", privateKeyField.getText().trim());
                    config.put("publicKey", publicKeyField.getText().trim());

                    cryptoEngines.put(name, config);

                    Vector<String> row = new Vector<>();
                    row.add(name);
                    row.add(config.get("algorithm"));
                    row.add(config.get("mode"));
                    row.add(config.get("padding"));
                    row.add(config.get("key"));
                    row.add(config.get("keyFormat"));
                    row.add(config.get("iv"));
                    row.add(config.get("ivFormat"));
                    row.add(config.get("privateKey"));
                    row.add(config.get("publicKey"));
                    ctyptoSettingTableModel.addRow(row);
                    break;
                }
            });
            // 编辑按钮事件
            ctyptoSettingEditButton.addActionListener(e -> {
                int selectedRow = ctyptoSettingtable.getSelectedRow();
                if (selectedRow == -1) {
                    JOptionPane.showMessageDialog(null, "请先选择要编辑的加解密器！");
                    return;
                }

                String originalName = (String) ctyptoSettingTableModel.getValueAt(selectedRow, 0);
                Map<String, String> oldConfig = cryptoEngines.get(originalName);

                // 安全获取每列数据，避免空值导致异常
                String name = (String) ctyptoSettingTableModel.getValueAt(selectedRow, 0);
                String algorithm = (String) ctyptoSettingTableModel.getValueAt(selectedRow, 1);
                String mode = (String) ctyptoSettingTableModel.getValueAt(selectedRow, 2);
                String padding = (String) ctyptoSettingTableModel.getValueAt(selectedRow, 3);
                String key = (String) ctyptoSettingTableModel.getValueAt(selectedRow, 4);
                String keyFormat = (String) ctyptoSettingTableModel.getValueAt(selectedRow, 5);
                String iv = (String) ctyptoSettingTableModel.getValueAt(selectedRow, 6);
                String ivFormat = (String) ctyptoSettingTableModel.getValueAt(selectedRow, 7);
                String privateKey = (String) ctyptoSettingTableModel.getValueAt(selectedRow, 8);
                String publicKey = (String) ctyptoSettingTableModel.getValueAt(selectedRow, 9);

                // 对可能为 null 的值做处理，避免空指针异常
                name = name == null ? "" : name;
                algorithm = algorithm == null ? "" : algorithm;
                mode = mode == null ? "" : mode;
                padding = padding == null ? "" : padding;
                key = key == null ? "" : key;
                keyFormat = keyFormat == null ? "" : keyFormat;
                iv = iv == null ? "" : iv;
                ivFormat = ivFormat == null ? "" : ivFormat;
                privateKey = privateKey == null ? "" : privateKey;
                publicKey = publicKey == null ? "" : publicKey;

                JPanel inputPanel = new JPanel(new GridLayout(11, 2, 10, 5));

                // 名称
                inputPanel.add(new JLabel("名称："));
                JTextField nameField = new JTextField(name);
                inputPanel.add(nameField);

                // algorithm
                inputPanel.add(new JLabel("algorithm："));
                JComboBox<String> algorithmCombo = new JComboBox<>(finalSupportedAlgorithm.toArray(new String[0]));
                algorithmCombo.setSelectedItem(algorithm);
                inputPanel.add(algorithmCombo);

                // mode
                inputPanel.add(new JLabel("mode："));
                JComboBox<String> modeCombo = new JComboBox<>(new String[]{"", "ECB", "CBC", "CFB", "OFB", "CTR", "GCM"});
                modeCombo.setSelectedItem(mode);
                inputPanel.add(modeCombo);

                // padding
                inputPanel.add(new JLabel("padding："));
                JComboBox<String> paddingCombo = new JComboBox<>(new String[]{"", "PKCS5Padding", "PKCS7Padding", "NoPadding", "ISO10126Padding"});
                paddingCombo.setSelectedItem(padding);
                inputPanel.add(paddingCombo);

                // key
                inputPanel.add(new JLabel("key："));
                JTextField keyField = new JTextField(key);
                inputPanel.add(keyField);

                // keyFormat
                inputPanel.add(new JLabel("keyFormat："));
                JComboBox<String> keyFormatCombo = new JComboBox<>(new String[]{"", "utf8", "base64", "hex"});
                keyFormatCombo.setSelectedItem(keyFormat);
                inputPanel.add(keyFormatCombo);

                // iv
                inputPanel.add(new JLabel("iv："));
                JTextField ivField = new JTextField(iv);
                inputPanel.add(ivField);

                // ivFormat
                inputPanel.add(new JLabel("ivFormat："));
                JComboBox<String> ivFormatCombo = new JComboBox<>(new String[]{"", "utf8", "base64", "hex"});
                ivFormatCombo.setSelectedItem(ivFormat);
                inputPanel.add(ivFormatCombo);

                // privateKey
                inputPanel.add(new JLabel("privateKey："));
                JTextField privateKeyField = new JTextField(privateKey);
                inputPanel.add(privateKeyField);

                // publicKey
                inputPanel.add(new JLabel("publicKey："));
                JTextField publicKeyField = new JTextField(publicKey);
                inputPanel.add(publicKeyField);

                int result = JOptionPane.showConfirmDialog(null, inputPanel, "编辑加解密器", JOptionPane.OK_CANCEL_OPTION);
                if (result == JOptionPane.OK_OPTION) {
                    String newName = nameField.getText().trim();
                    if (newName.isEmpty()) {
                        JOptionPane.showMessageDialog(null, "名称不能为空！");
                        return;
                    }
                    if (!newName.equals(originalName) && cryptoEngines.containsKey(newName)) {
                        JOptionPane.showMessageDialog(null, "名称已存在，不能重复！");
                        return;
                    }

                    // 收集新配置
                    Map<String, String> newConfig = new LinkedHashMap<>();
                    newConfig.put("algorithm", (String) algorithmCombo.getSelectedItem());
                    newConfig.put("mode", (String) modeCombo.getSelectedItem());
                    newConfig.put("padding", (String) paddingCombo.getSelectedItem());
                    newConfig.put("key", keyField.getText().trim());
                    newConfig.put("keyFormat", (String) keyFormatCombo.getSelectedItem());
                    newConfig.put("iv", ivField.getText().trim());
                    newConfig.put("ivFormat", (String) ivFormatCombo.getSelectedItem());
                    newConfig.put("privateKey", privateKeyField.getText().trim());
                    newConfig.put("publicKey", publicKeyField.getText().trim());

                    // 替换 map 中的 key
                    cryptoEngines.remove(originalName);
                    cryptoEngines.put(newName, newConfig);

                    // 更新表格
                    ctyptoSettingTableModel.setValueAt(newName, selectedRow, 0);
                    ctyptoSettingTableModel.setValueAt(newConfig.get("algorithm"), selectedRow, 1);
                    ctyptoSettingTableModel.setValueAt(newConfig.get("mode"), selectedRow, 2);
                    ctyptoSettingTableModel.setValueAt(newConfig.get("padding"), selectedRow, 3);
                    ctyptoSettingTableModel.setValueAt(newConfig.get("key"), selectedRow, 4);
                    ctyptoSettingTableModel.setValueAt(newConfig.get("keyFormat"), selectedRow, 5);
                    ctyptoSettingTableModel.setValueAt(newConfig.get("iv"), selectedRow, 6);
                    ctyptoSettingTableModel.setValueAt(newConfig.get("ivFormat"), selectedRow, 7);
                    ctyptoSettingTableModel.setValueAt(newConfig.get("privateKey"), selectedRow, 8);
                    ctyptoSettingTableModel.setValueAt(newConfig.get("publicKey"), selectedRow, 9);
                }
            });
            // 删除按钮事件
            ctyptoSettingDeleteButton.addActionListener(e -> {
                int selectedRow = ctyptoSettingtable.getSelectedRow();
                if (selectedRow == -1) {
                    JOptionPane.showMessageDialog(null, "请先选择要删除的加解密器！");
                    return;
                }

                String name = (String) ctyptoSettingTableModel.getValueAt(selectedRow, 0);
                int confirm = JOptionPane.showConfirmDialog(null, "确认删除 '" + name + "' 吗？", "删除确认", JOptionPane.YES_NO_OPTION);
                if (confirm == JOptionPane.YES_OPTION) {
                    cryptoEngines.remove(name);
                    ctyptoSettingTableModel.removeRow(selectedRow);
                }
            });
            // 清空按钮事件
            ctyptoSettingClearButton.addActionListener(e -> {
                int confirm = JOptionPane.showConfirmDialog(null, "确定要清空所有加解密器配置吗？", "确认清空", JOptionPane.YES_NO_OPTION);
                if (confirm == JOptionPane.YES_OPTION) {
                    cryptoEngines.clear();
                    ctyptoSettingTableModel.setRowCount(0);
                }
            });
            // 保存按钮事件
            ctyptoSettingSaveButton.addActionListener(e -> {
                try {
                    Map<String, Object> finalYamlMap = new LinkedHashMap<>();

                    // 保留 supportedAlgorithm 原值
                    finalYamlMap.put("supportedAlgorithm", finalSupportedAlgorithm);

                    // 构造 cryptoEngines
                    Map<String, Map<String, String>> cryptoEnginesMap = new LinkedHashMap<>();
                    for (int i = 0; i < ctyptoSettingTableModel.getRowCount(); i++) {
                        String name = (String) ctyptoSettingTableModel.getValueAt(i, 0);
                        Map<String, String> config = new LinkedHashMap<>();
                        config.put("algorithm", (String) ctyptoSettingTableModel.getValueAt(i, 1));
                        config.put("mode", (String) ctyptoSettingTableModel.getValueAt(i, 2));
                        config.put("padding", (String) ctyptoSettingTableModel.getValueAt(i, 3));
                        config.put("key", (String) ctyptoSettingTableModel.getValueAt(i, 4));
                        config.put("keyFormat", (String) ctyptoSettingTableModel.getValueAt(i, 5));
                        config.put("iv", (String) ctyptoSettingTableModel.getValueAt(i, 6));
                        config.put("ivFormat", (String) ctyptoSettingTableModel.getValueAt(i, 7));
                        config.put("privateKey", (String) ctyptoSettingTableModel.getValueAt(i, 8));
                        config.put("publicKey", (String) ctyptoSettingTableModel.getValueAt(i, 9));
                        cryptoEnginesMap.put(name, config);
                    }
                    finalYamlMap.put("cryptoEngines", cryptoEnginesMap);

                    // 写入 YAML
                    DumperOptions options = new DumperOptions();
                    options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
                    options.setIndent(2);
                    options.setPrettyFlow(true);
                    options.setDefaultScalarStyle(DumperOptions.ScalarStyle.DOUBLE_QUOTED); // 保持引号

                    Yaml yaml = new Yaml(options);
                    FileWriter writer = new FileWriter(cryptoConfigFilePath);
                    yaml.dump(finalYamlMap, writer);
                    writer.close();

                    JOptionPane.showMessageDialog(null, "配置已成功保存！");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "保存配置失败：" + ex.getMessage());
                }
            });
            // 恢复默认按钮事件
            ctyptoSettingResetButton.addActionListener(e -> {
                // 先清空内存中的配置，防止重复
                cryptoEngines.clear();
                int confirm = JOptionPane.showConfirmDialog(null, "确认恢复默认配置？当前数据将被清除", "确认恢复", JOptionPane.YES_NO_OPTION);
                if (confirm != JOptionPane.YES_OPTION) return;
                try (InputStream in = getClass().getClassLoader().getResourceAsStream("cryptoConfig.yaml")) {
                    if (in == null) {
                        JOptionPane.showMessageDialog(null, "未找到默认配置文件 cryptoConfig.yaml", "错误", JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                    // JDK 8兼容的读取方式
                    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                    byte[] temp = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = in.read(temp)) != -1) {
                        buffer.write(temp, 0, bytesRead);
                    }
                    // 写入目标配置文件
                    Files.write(Paths.get(cryptoConfigFilePath), buffer.toByteArray());

                    // =================== 加载写入后的配置并刷新表格 ===================
                    try (InputStream configInput = Files.newInputStream(Paths.get(cryptoConfigFilePath))) {
                        Yaml yaml = new Yaml();
                        Map<String, Object> yamlData = yaml.load(configInput);
                        Map<String, Object> engines = (Map<String, Object>) yamlData.get("cryptoEngines");
                        ctyptoSettingTableModel.setRowCount(0); // 清空表格
                        for (Map.Entry<String, Object> entry : engines.entrySet()) {
                            String name = entry.getKey();
                            Map<String, String> engine = (Map<String, String>) entry.getValue();
                            ctyptoSettingTableModel.addRow(new Object[]{
                                    name,
                                    engine.get("algorithm"),
                                    engine.get("mode"),
                                    engine.get("padding"),
                                    engine.get("key"),
                                    engine.get("keyFormat"),
                                    engine.get("iv"),
                                    engine.get("ivFormat"),
                                    engine.get("privateKey"),
                                    engine.get("publicKey")
                            });
                        }
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(null, "配置加载失败：" + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                    }
                    // ===========================================================
                    JOptionPane.showMessageDialog(null, "默认配置已恢复。");
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(null, "恢复失败：" + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                }
            });
            // 表格编辑
            ctyptoSettingtable.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2) {
                        ctyptoSettingEditButton.doClick();
                    }
                }
            });
            // 初始化表格
            // 初始化时直接写在你的构造函数或init方法中
            try {
                InputStream input = Files.newInputStream(Paths.get(cryptoConfigFilePath));
                Yaml yaml = new Yaml();
                Map<String, Object> yamlData = yaml.load(input);
                input.close();

                Map<String, Object> engines = (Map<String, Object>) yamlData.get("cryptoEngines");

                // 清空表格
                ctyptoSettingTableModel.setRowCount(0);

                for (Map.Entry<String, Object> entry : engines.entrySet()) {
                    String name = entry.getKey();
                    Map<String, String> engine = (Map<String, String>) entry.getValue();
                    ctyptoSettingTableModel.addRow(new Object[]{
                            name,
                            engine.get("algorithm"),
                            engine.get("mode"),
                            engine.get("padding"),
                            engine.get("key"),
                            engine.get("keyFormat"),
                            engine.get("iv"),
                            engine.get("ivFormat"),
                            engine.get("privateKey"),
                            engine.get("publicKey")
                    });
                }
            } catch (Exception e) {
                stderr.println("配置加载失败:" + e.getMessage());
            }

            // =================== 添加到标签栏 ===================
            tabbedPane.addTab("插件设置", null, mainPanel, "插件主要设置相关");
            tabbedPane.addTab("加解密器配置", null, cryptoPanel, "加解密器配置相关");

            callbacks.addSuiteTab(this);
        });
    }

    @Override
    public String getTabCaption() {
        return extensionName;
    }

    @Override
    public Component getUiComponent() {
        return tabbedPane;
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    /**
     * Processes an HTTP message.
     * @param toolFlag A flag indicating the Burp tool that issued the request.
     * Burp tool flags are defined in the
     * <code>IBurpExtenderCallbacks</code> interface.
     * @param messageIsRequest Flags whether the method is being invoked for a
     * request or response.
     * @param messageInfo Details of the request / response to be processed.
     * Extensions can call the setter methods on this object to update the
     * current message and so modify Burp's behavior.
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        helpers = callbacks.getHelpers();
        try {
            String configContent = Tools.readFileToString(configFilePath);
            JSONObject settingConfig = JSON.parseObject(configContent);
            JSONArray enabledComponents = settingConfig.getJSONArray("enabledComponents");
            String requestLocation = settingConfig.getString("requestLocation");

            // 检查是否启用了插件
            if (enabledComponents.contains("是否启用插件")) {
                // 判断是否满足起用的工具标识
                if (ToolComponentChecker.checkToolFlag(enabledComponents, toolFlag)) {
                    // ===================================== 判断是否满足白名单 =====================================
                    if (isWhitelisted(messageInfo, settingConfig.getString("whitelist"))) {
                        // ===================================== 处理请求 =====================================
                        if (messageIsRequest) {
                            // 处理请求体
                            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
                            // 处理请求头
                            List<String> requestHeaders = new ArrayList<>(requestInfo.getHeaders());
                            System.out.println("处理" + toolFlag + "工具的请求");
                            System.out.println(requestLocation);
                            // =============================================== 判断请求处理的位置 ================================================
                            // ====================================================== 请求体 ===================================================
                            if (requestLocation.equals("请求体")) {
                                System.out.println("请求体");
                                // 获取请求体的偏移量
                                int bodyOffset = requestInfo.getBodyOffset();
                                // 获取整个请求的字节码
                                byte[] byte_Request = messageInfo.getRequest();
                                String request = new String(byte_Request);
                                // 通过偏移量截取请求体
                                String body = request.substring(bodyOffset);
                                // 获取加密器顺序（从 JSON 中获取）
                                String jsonText = Tools.readFileToString(configFilePath);
                                JSONObject jsonConfig = JSON.parseObject(jsonText);
                                String cryptoOrderStr = jsonConfig.getString("requestCryptoOrder");
                                if (cryptoOrderStr == null || cryptoOrderStr.trim().isEmpty()) {
                                    callbacks.printError("未配置 requestCryptoOrder 字段或为空");
                                    return;
                                }
                                String[] encryptEngines = cryptoOrderStr.split(",");
                                // 获取加密器配置
                                Yaml yaml = new Yaml();
                                Map<String, Object> yamlConfig = yaml.load(Files.newInputStream(Paths.get(cryptoConfigFilePath)));
                                Map<String, Map<String, Object>> cryptoEngines = (Map<String, Map<String, Object>>) yamlConfig.get("cryptoEngines");
                                // 遍历处理
                                String data = body;
                                for (String engineName : encryptEngines) {
                                    engineName = engineName.trim(); // 去除前后空格
                                    Map<String, Object> engineConfig = cryptoEngines.get(engineName);
                                    Map<String, String> params = new HashMap<>();
                                    if (engineConfig != null) {
                                        for (Map.Entry<String, Object> entry : engineConfig.entrySet()) {
                                            System.out.println(entry.getKey() + ": " + entry.getValue());
                                            params.put(entry.getKey(), entry.getValue().toString());
                                        }
                                        data = CryptoEngine.encrypt(data, params);
                                    } else {
                                        callbacks.printError("未找到加密器配置: " + engineName);
                                    }
                                }
                                // 转换回字节码
                                byte[] byte_body = data.getBytes();
                                byte[] new_request = helpers.buildHttpMessage(requestHeaders, byte_body);
                                messageInfo.setRequest(new_request);
                            }
                            // ============================================================== GET参数 =================================================
//                            else if (requestLocation.equals("GET参数") | requestLocation.equals("POST参数") | requestLocation.equals("GET和POST参数")) {
//                                // ================================== 普通类型 =================================
//                                // 确认用户选择的需要处理的参数类型，选择GET就不处理POST
//                                int expectedType = "POST参数".equals(requestLocation) ? IParameter.PARAM_BODY : IParameter.PARAM_URL;
//                                if (requestLocation.equals("GET和POST参数")){
//                                    expectedType = 2;
//                                }
//                                // 获取所有参数信息
//                                List<IParameter> parameters = requestInfo.getParameters();
//                                // 获取加密规则
//                                List<Map<String, Object>> requestRules = (List<Map<String, Object>>) settingConfig.get("requestRules");
//                                // 获取初始请求包，用于更新参数
//                                byte[] updatedRequest = messageInfo.getRequest();
//                                // 创建一个Map用于处理json格式的post请求
//                                Map<String, String> postParams = new HashMap<>();
//                                // 遍历处理参数
//                                for (IParameter param : parameters) {
//                                    // 获取初始参数值，放在最外层for防止被重置
//                                    String paramData = param.getValue();
//                                    // 跳过/不跳过处理
//                                    if (expectedType != 2){
//                                        if (param.getType() != expectedType) {
//                                            System.out.println("跳过处理");
//                                            continue;
//                                        }
//                                    }
//                                    System.out.println(param.getName() + ":" + param.getType());
//                                    // 遍历配置文件中所有的 requestRules
//                                    for (Map<String, Object> rule : requestRules) {
//                                        String paramName = (String) rule.get("paramName");
//                                        String paramType = (String) rule.get("paramType");
//                                        int paramTypeNum = rule.get("paramType").equals("GET") ? IParameter.PARAM_URL : IParameter.PARAM_BODY;
//                                        String cryptoName = (String) rule.get("cryptoName");
//                                        if (param.getName().equals(paramName)) {
//                                            System.out.println("=====================");
//                                            System.out.println("匹配参数: " + paramName);
//                                            System.out.println("参数类型: " + paramType + "，加解密算法: " + cryptoName);
//                                            System.out.println("名称匹配成功");
//                                            System.out.println("=====================");
//                                            // 开始匹配类型
//                                            if (param.getType() == paramTypeNum) {
//                                                // 获取加密器配置
//                                                Yaml yaml = new Yaml();
//                                                Map<String, Object> yamlConfig = yaml.load(Files.newInputStream(Paths.get(cryptoConfigFilePath)));
//                                                Map<String, Map<String, Object>> cryptoEngines = (Map<String, Map<String, Object>>) yamlConfig.get("cryptoEngines");
//                                                String[] encryptEngines = cryptoName.split(",");
//                                                for (String engineName : encryptEngines) {
//                                                    engineName = engineName.trim(); // 去除前后空格
//                                                    Map<String, Object> engineConfig = cryptoEngines.get(engineName);
//                                                    Map<String, String> params = new HashMap<>();
//                                                    if (engineConfig != null) {
//                                                        for (Map.Entry<String, Object> entry : engineConfig.entrySet()) {
//                                                            System.out.println(entry.getKey() + ": " + entry.getValue());
//                                                            params.put(entry.getKey(), entry.getValue().toString());
//                                                        }
//                                                        paramData = CryptoEngine.encrypt(paramData, params);
//                                                        // 分参数类型来处理，json格式
//                                                        IParameter newParam = helpers.buildParameter(param.getName(), paramData, param.getType());
//                                                        updatedRequest = helpers.updateParameter(updatedRequest, newParam);
//                                                    } else {
//                                                        callbacks.printError("未找到加密器配置: " + engineName);
//                                                    }
//                                                }
//                                            }
//                                        }
//                                    }
//                                }
//                                messageInfo.setRequest(updatedRequest);
//                            }
                            else if (requestLocation.equals("GET参数") | requestLocation.equals("POST参数") | requestLocation.equals("GET和POST参数")) {
                                // ================================== 普通类型 =================================
                                int expectedType = "POST参数".equals(requestLocation) ? IParameter.PARAM_BODY : IParameter.PARAM_URL;
                                if (requestLocation.equals("GET和POST参数")) {
                                    expectedType = 2;
                                }

                                List<IParameter> parameters = requestInfo.getParameters();
                                List<Map<String, Object>> requestRules = (List<Map<String, Object>>) settingConfig.get("requestRules");
                                byte[] updatedRequest = messageInfo.getRequest();

                                boolean isJsonRequest = false;
                                for (String header : requestInfo.getHeaders()) {
                                    if (header.toLowerCase().startsWith("content-type:") && header.toLowerCase().contains("application/json")) {
                                        isJsonRequest = true;
                                        break;
                                    }
                                }

                                // =============== 处理 application/json 的 POST 请求体 ==================
                                if (isJsonRequest && (expectedType == IParameter.PARAM_BODY || expectedType == 2) && settingConfig.getString("paramType").equals("JSON")) {
                                    int bodyOffset = requestInfo.getBodyOffset();
                                    String body = new String(updatedRequest, bodyOffset, updatedRequest.length - bodyOffset);
                                    JSONObject jsonObj = JSON.parseObject(body);

                                    for (Map<String, Object> rule : requestRules) {
                                        String paramName = (String) rule.get("paramName");
                                        String paramType = (String) rule.get("paramType");
                                        String cryptoName = (String) rule.get("cryptoName");

                                        if (!"POST".equalsIgnoreCase(paramType)) continue;
                                        if (!jsonObj.containsKey(paramName)) continue;

                                        String paramData = jsonObj.getString(paramName);
                                        System.out.println("匹配 JSON 参数: " + paramName + "，值: " + paramData);

                                        // 加密处理
                                        Yaml yaml = new Yaml();
                                        Map<String, Object> yamlConfig = yaml.load(Files.newInputStream(Paths.get(cryptoConfigFilePath)));
                                        Map<String, Map<String, Object>> cryptoEngines = (Map<String, Map<String, Object>>) yamlConfig.get("cryptoEngines");

                                        String[] encryptEngines = cryptoName.split(",");
                                        for (String engineName : encryptEngines) {
                                            engineName = engineName.trim();
                                            Map<String, Object> engineConfig = cryptoEngines.get(engineName);
                                            if (engineConfig != null) {
                                                Map<String, String> params = new HashMap<>();
                                                for (Map.Entry<String, Object> entry : engineConfig.entrySet()) {
                                                    params.put(entry.getKey(), entry.getValue().toString());
                                                }
                                                paramData = CryptoEngine.encrypt(paramData, params);
                                            } else {
                                                callbacks.printError("未找到加密器配置: " + engineName);
                                            }
                                        }
                                        // 更新 JSON 对象中的值
                                        jsonObj.put(paramName, paramData);
                                    }

                                    // 构造新请求体并更新
                                    String newJsonBody = jsonObj.toJSONString();
                                    byte[] newRequest = helpers.buildHttpMessage(requestInfo.getHeaders(), newJsonBody.getBytes());
                                    messageInfo.setRequest(newRequest);
                                    // 处理之后更新updatedRequest和expectedType，用于还需要处理GET参数的情况
                                    expectedType = IParameter.PARAM_URL;
                                    updatedRequest = messageInfo.getRequest();
                                }

                                // ============== 普通参数处理逻辑 ==============
                                for (IParameter param : parameters) {
                                    String paramData = param.getValue();

                                    if (expectedType != 2 && param.getType() != expectedType) {
                                        System.out.println("跳过处理");
                                        continue;
                                    }

                                    System.out.println(param.getName() + ":" + param.getType());

                                    for (Map<String, Object> rule : requestRules) {
                                        String paramName = (String) rule.get("paramName");
                                        String paramType = (String) rule.get("paramType");
                                        int paramTypeNum = "GET".equals(paramType) ? IParameter.PARAM_URL : IParameter.PARAM_BODY;
                                        String cryptoName = (String) rule.get("cryptoName");

                                        if (param.getName().equals(paramName) && param.getType() == paramTypeNum) {
                                            System.out.println("=====================");
                                            System.out.println("匹配参数: " + paramName);
                                            System.out.println("参数类型: " + paramType + "，加解密算法: " + cryptoName);
                                            System.out.println("=====================");

                                            Yaml yaml = new Yaml();
                                            Map<String, Object> yamlConfig = yaml.load(Files.newInputStream(Paths.get(cryptoConfigFilePath)));
                                            Map<String, Map<String, Object>> cryptoEngines = (Map<String, Map<String, Object>>) yamlConfig.get("cryptoEngines");
                                            String[] encryptEngines = cryptoName.split(",");

                                            for (String engineName : encryptEngines) {
                                                engineName = engineName.trim();
                                                Map<String, Object> engineConfig = cryptoEngines.get(engineName);
                                                Map<String, String> params = new HashMap<>();
                                                if (engineConfig != null) {
                                                    for (Map.Entry<String, Object> entry : engineConfig.entrySet()) {
                                                        params.put(entry.getKey(), entry.getValue().toString());
                                                    }
                                                    paramData = CryptoEngine.encrypt(paramData, params);
                                                    IParameter newParam = helpers.buildParameter(param.getName(), paramData, param.getType());
                                                    updatedRequest = helpers.updateParameter(updatedRequest, newParam);
                                                } else {
                                                    callbacks.printError("未找到加密器配置: " + engineName);
                                                }
                                            }
                                        }
                                    }
                                }
                                messageInfo.setRequest(updatedRequest);
                            }
                        }
                        // ====================================================== 处理响应 ===================================================
                        else {
                            // 处理响应头
                            IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());
                            // 处理响应头
                            List<String> responseHeaders = new ArrayList<>(responseInfo.getHeaders());

                            System.out.println("处理" + toolFlag + "工具的响应");
                            String responseLocation = settingConfig.getString("responseLocation");
                            if ("不处理".equals(responseLocation)) {
                                return;
                            }
                            byte[] response = messageInfo.getResponse();
                            int bodyOffset = responseInfo.getBodyOffset();
                            String responseBody = new String(response, bodyOffset, response.length - bodyOffset);
                            // 获取响应解密规则
                            List<Map<String, Object>> responseRules = (List<Map<String, Object>>) settingConfig.get("responseRules");
                            // 加载加密配置
                            Yaml yaml = new Yaml();
                            Map<String, Object> yamlConfig = yaml.load(Files.newInputStream(Paths.get(cryptoConfigFilePath)));
                            Map<String, Map<String, Object>> cryptoEngines = (Map<String, Map<String, Object>>) yamlConfig.get("cryptoEngines");
                            String decryptedResult = null;
                            if ("JSON格式参数".equals(responseLocation)) {
                                // 尝试解析为 JSON
                                JSONObject jsonObj;
                                try {
                                    jsonObj = JSON.parseObject(responseBody);
                                } catch (Exception e) {
                                    callbacks.printError("响应不是合法的 JSON 格式，无法解析！");
                                    return;
                                }

                                for (Map<String, Object> rule : responseRules) {
                                    String paramName = (String) rule.get("paramName");
                                    String cryptoName = (String) rule.get("cryptoName");

                                    if (!jsonObj.containsKey(paramName)) continue;

                                    String encryptedValue = jsonObj.getString(paramName);
                                    System.out.println("匹配响应字段: " + paramName + "，加密值: " + encryptedValue);

                                    String[] engines = cryptoName.split(",");
                                    for (String engineName : engines) {
                                        engineName = engineName.trim();
                                        Map<String, Object> engineConfig = cryptoEngines.get(engineName);

                                        if (engineConfig == null) {
                                            callbacks.printError("未找到响应解密器配置: " + engineName);
                                            continue;
                                        }

                                        Map<String, String> params = new HashMap<>();
                                        for (Map.Entry<String, Object> entry : engineConfig.entrySet()) {
                                            params.put(entry.getKey(), entry.getValue().toString());
                                        }

                                        encryptedValue = CryptoEngine.decrypt(encryptedValue, params);
                                    }

                                    jsonObj.put(paramName, encryptedValue);
                                }

                                decryptedResult = jsonObj.toJSONString();
                            }
                            // 整个响应体解密（逐个解密器尝试）
                            else if ("响应体".equals(responseLocation)) {
                                String encryptedBody = responseBody;

                                for (Map<String, Object> rule : responseRules) {
                                    String cryptoName = (String) rule.get("cryptoName");

                                    String[] engines = cryptoName.split(",");
                                    for (String engineName : engines) {
                                        engineName = engineName.trim();
                                        Map<String, Object> engineConfig = cryptoEngines.get(engineName);

                                        if (engineConfig == null) {
                                            callbacks.printError("未找到响应解密器配置: " + engineName);
                                            continue;
                                        }

                                        Map<String, String> params = new HashMap<>();
                                        for (Map.Entry<String, Object> entry : engineConfig.entrySet()) {
                                            params.put(entry.getKey(), entry.getValue().toString());
                                        }

                                        encryptedBody = CryptoEngine.decrypt(encryptedBody, params);
                                    }

                                    decryptedResult = encryptedBody;
                                    break; // 只处理一次
                                }
                            }
                            // 更新响应包
                            if (decryptedResult != null) {
                                byte[] newBody = decryptedResult.getBytes(StandardCharsets.UTF_8);
                                messageInfo.setResponse(helpers.buildHttpMessage(responseHeaders, newBody));
                            } else {
                                callbacks.printError("解密失败，无法生成新的响应体。");
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 判断请求是否在白名单内
     * @param messageInfo 请求信息
     * @param whitelistRaw 白名单配置
     * @return 是否在白名单内
     */
    public boolean isWhitelisted(IHttpRequestResponse messageInfo, String whitelistRaw) {
        if (whitelistRaw == null || whitelistRaw.isEmpty()) return false;

        String[] rules = whitelistRaw.split("\\n");
        URL url = helpers.analyzeRequest(messageInfo).getUrl();
        String fullUrl = url.toString();
        String host = url.getHost();
        String port = url.getPort() == -1 ? "" : ":" + url.getPort();
        host = host + port;

        for (String rule : rules) {
            rule = rule.trim();
            if (rule.isEmpty()) continue;

            // 完整 URL 前缀匹配
            if (rule.startsWith("http://") || rule.startsWith("https://")) {
                // 这里因为burp的getUrl会自动加上端口，所以需要去掉
                if(fullUrl.startsWith("https://")){
                    fullUrl = fullUrl.replace(":443","");
                }
                System.out.println("完整 URL 前缀匹配: " + rule + " vs " + fullUrl);
                if (fullUrl.startsWith(rule)) {
                    return true;
                }
            } else {
                // 域名完全匹配（忽略大小写）
                if (host.equalsIgnoreCase(rule)) {
                    System.out.println("域名完全匹配: " + rule + " vs " + fullUrl);
                    return true;
                }
            }
        }
        return false;
    }
}