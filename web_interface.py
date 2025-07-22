import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash
import logging
from math import ceil
from urllib.parse import unquote
import sys
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# 自定义简洁日志格式
class SimpleFormatter(logging.Formatter):
    def format(self, record):
        if record.name == 'werkzeug':
            if 'HTTP' in record.msg:
                # 提取并简化访问日志
                parts = record.msg.split('"')
                if len(parts) > 1:
                    method_path = parts[1].split()
                    if len(method_path) > 1:
                        method = method_path[0]
                        path = method_path[1].split('?')[0]  # 移除查询参数
                        status = record.msg.split()[-1]
                        return f"{method} {path} -> {status}"
            return record.msg
        else:
            return f"[{record.levelname}] {record.msg}"

# 设置日志
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# 创建控制台处理器并设置自定义格式
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(SimpleFormatter())
logger.addHandler(console_handler)

# 禁用 Flask 的默认日志
logging.getLogger('werkzeug').setLevel(logging.WARNING)

# 数据库路径（与主脚本一致）
DB_PATH = os.getenv("DB_PATH", "/data/bot123.db")

def get_directory_contents(path, page=1, per_page=100, sort_order='asc'):
    """
    获取指定路径下的内容（带分页和排序）
    sort_order: 排序方向 (asc, desc)
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 查询目录下的子目录
    dirs = set()
    # 添加结尾斜杠确保精确匹配
    search_path = path + '/' if path else ''
    
    # 修复路径层级问题
    cursor.execute("""
        SELECT file_path
        FROM file_records
        WHERE file_path LIKE ? || '%'
    """, (search_path,))
    
    for row in cursor.fetchall():
        full_path = row[0]
        # 精确提取直接子目录
        if full_path.startswith(search_path):
            rel_path = full_path[len(search_path):]
            if '/' in rel_path:
                # 只取第一级目录名
                first_dir = rel_path.split('/')[0]
                if first_dir:
                    dirs.add(first_dir)
    
    # 排序
    dirs = sorted(dirs)
    
    # 获取当前路径下的文件
    cursor.execute("""
        SELECT id, file_name, size, created_at
        FROM file_records
        WHERE file_path LIKE ? AND file_path NOT LIKE ? || '/%'
    """, (search_path + '%', search_path + '%'))
    
    files = []
    for row in cursor.fetchall():
        file_id, file_name, size, created_at = row
        files.append({
            'id': file_id,
            'name': file_name,
            'size': size,
            'created_at': created_at,
            'type': 'file'
        })
    
    # 合并目录和文件
    items = []
    for dir_name in dirs:
        items.append({
            'name': dir_name,
            'type': 'directory'
        })
    
    for file in files:
        items.append(file)
    
    # 修复：确保目录始终在文件前面
    directories = [item for item in items if item['type'] == 'directory']
    files = [item for item in items if item['type'] == 'file']
    
    # 排序逻辑
    reverse_order = (sort_order == 'desc')
    
    # 先按类型排序（目录在前），再按名称排序
    directories.sort(key=lambda x: x['name'].lower(), reverse=reverse_order)
    files.sort(key=lambda x: x['name'].lower(), reverse=reverse_order)
    
    # 重新组合
    items = directories + files
    
    # 计算分页
    start = (page - 1) * per_page
    end = start + per_page
    paginated_items = items[start:end]
    
    # 计算总页数
    total_items = len(items)
    total_pages = ceil(total_items / per_page) if total_items > 0 else 1
    
    conn.close()
    return paginated_items, total_items, total_pages

@app.route('/')
@app.route('/browse')
def browse_path():
    """浏览指定路径（带分页和排序）"""
    path = request.args.get('path', '')
    # 规范化路径：确保没有尾部斜杠
    if path and path.endswith('/'):
        path = path[:-1]
    
    page = request.args.get('page', 1, type=int)
    sort_order = request.args.get('sort_order', 'asc')
    per_page = 100  # 每页100条
    
    # 获取面包屑导航
    breadcrumbs = []
    if path:
        parts = path.split('/')
        current_path = ""
        for i in range(len(parts)):
            # 修复：正确构建路径部分
            current_path = current_path + parts[i] if not current_path else current_path + '/' + parts[i]
            breadcrumbs.append({
                'name': parts[i],
                'path': current_path
            })
    
    # 获取目录内容（带分页和排序）
    items, total_items, total_pages = get_directory_contents(
        path, page, per_page, sort_order
    )
    
    return render_template('browse.html', 
                          path=path,
                          breadcrumbs=breadcrumbs,
                          items=items,
                          page=page,
                          total_pages=total_pages,
                          total_items=total_items,
                          search_results=None,
                          search_keyword=None,
                          sort_order=sort_order)

@app.route('/delete', methods=['POST'])
def delete_file():
    """删除文件记录"""
    file_id = request.form.get('file_id')
    path = request.form.get('path', '')
    page = request.form.get('page', 1, type=int)
    sort_order = request.form.get('sort_order', 'asc')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM file_records WHERE id = ?", (file_id,))
        conn.commit()
        flash(f"成功删除文件记录 ID: {file_id}", "success")
        logger.info(f"Deleted file ID: {file_id}")
    except Exception as e:
        conn.rollback()
        flash(f"删除失败: {str(e)}", "danger")
        logger.error(f"Delete failed: {str(e)}")
    finally:
        conn.close()
    
    return redirect(url_for('browse_path', 
                           path=path, 
                           page=page,
                           sort_order=sort_order))

@app.route('/delete_dir', methods=['POST'])
def delete_directory():
    """删除目录及其所有内容"""
    dir_path = request.form.get('dir_path')
    current_path = request.form.get('current_path', '')
    page = request.form.get('page', 1, type=int)
    sort_order = request.form.get('sort_order', 'asc')
    
    if not dir_path:
        flash("未指定目录路径", "danger")
        logger.warning("Directory delete attempt without path")
        return redirect(url_for('browse_path', 
                               path=current_path, 
                               page=page,
                               sort_order=sort_order))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # 删除目录及其所有子目录和文件
        cursor.execute("""
            DELETE FROM file_records 
            WHERE file_path LIKE ? || '/%' 
            OR file_path = ?
        """, (dir_path, dir_path))
        
        conn.commit()
        flash(f"成功删除目录: {dir_path} 及其所有内容", "success")
        logger.info(f"Deleted directory: {dir_path}")
    except Exception as e:
        conn.rollback()
        flash(f"删除目录失败: {str(e)}", "danger")
        logger.error(f"Directory delete failed: {str(e)}")
    finally:
        conn.close()
    
    return redirect(url_for('browse_path', 
                           path=current_path, 
                           page=page,
                           sort_order=sort_order))

@app.route('/search')
def search_files():
    """搜索媒体文件"""
    keyword = request.args.get('keyword', '')
    if not keyword:
        flash("请输入搜索关键词", "warning")
        logger.info("Empty search attempt")
        return redirect(url_for('browse_path'))
    
    logger.info(f"Search initiated for: {keyword}")
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # 在media_name字段上进行模糊搜索
        cursor.execute("""
            SELECT DISTINCT media_name, media_type, file_path
            FROM file_records 
            WHERE media_name LIKE ? 
            ORDER BY media_name, file_path
        """, ('%'+keyword+'%',))
        
        results = cursor.fetchall()
        
        # 按媒体名称分组
        media_groups = {}
        for row in results:
            media_name = row['media_name'] or '未知媒体'
            # 修复：使用文件路径的目录部分作为文件夹路径
            file_path = row['file_path']
            # 确保路径格式正确
            if file_path:
                # 获取文件所在目录
                folder_path = os.path.dirname(file_path)
                # 标准化路径
                folder_path = folder_path.rstrip('/')
            else:
                folder_path = ''
            
            if media_name not in media_groups:
                media_groups[media_name] = {
                    'name': media_name,
                    'type': row['media_type'],
                    'folder_path': folder_path
                }
        
        # 转换为列表并排序
        grouped_results = sorted(media_groups.values(), key=lambda x: x['name'])
        
        logger.info(f"Search completed: {len(grouped_results)} results found")
        return render_template('browse.html',
                              path=None,
                              breadcrumbs=[],
                              items=[],
                              page=1,
                              total_pages=1,
                              total_items=0,
                              search_results=grouped_results,
                              search_keyword=keyword,
                              sort_order='asc')
    except Exception as e:
        logger.error(f"Search failed: {str(e)}")
        flash(f"搜索失败: {str(e)}", "danger")
        return redirect(url_for('browse_path'))
    finally:
        conn.close()

def print_startup_message():
    """打印美观的启动信息"""
    print("\n" + "=" * 60)
    print(f" 123Cloud Media Browser - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print(f" • Running on: http://0.0.0.0:8122")
    print(f" • Database: {DB_PATH}")
    print(f" • Press CTRL+C to stop")
    print("=" * 60 + "\n")

if __name__ == '__main__':
    print_startup_message()
    app.run(host='::', port=8122, debug=False)
