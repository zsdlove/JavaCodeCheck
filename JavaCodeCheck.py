import os
import sys
import xml.dom.minidom
#resultinfo={"xss":[item1,item2]},{}}  item={"path":"path","line":"line","linecode":"linecode"}
resultinfo={}
def banner_bigin():
	print(" "*45+"#"*10+"#"*45)
	print(" "*44+"#"+" "*3+"死"+" "+"不"+" "*2+"#"+" "*43+"#")
	print(" "*43+"#"+" "*4+"生"+" "+"服"+" "*3+"#"+" "*42+"#")
	print(" "*42+"#"+" "*5+"看"+" "+"就"+" "*4+"#"+" "*41+"#")	
	print(" "*41+"#"+" "*6+"淡"+" "+"干"+" "*5+"#"+" "*40+"#")
	print("#"*40+"开始输出白盒扫描结果"+"#"*40)
	print(" "*40+"#powered by zsdlove#"+" "*39+"#")
	print(" "*41+"#"+" "*6+"任"+" "+"行"+" "*5+"#"+" "*40+"#")
	print(" "*42+"#"+" "*5+"重"+" "+"道"+" "*4+"#"+" "*41+"#")
	print(" "*43+"#"+" "*4+"者"+" "+"远"+" "*3+"#"+" "*42+"#")
	print(" "*44+"#"*12+"#"*44)
def banner_finished():
	print(" "*84+"#"+"#"*15)
	print(" "*84+"#"+" "*3)
	print("#"*84+"#"*5+"#结束#"+"#"*5)
	print(" "*84+"#"+" "*3)
	print(" "*84+"#"+"#"*15)
def getFeatureFromXml():
	vulhub={}
	dom = xml.dom.minidom.parse('conf.xml')
	root = dom.documentElement
	nodelist=root.childNodes
	for node in nodelist:
		if node.nodeName!="#text":
			#print(node.nodeName)
			vulname=node.nodeName
			for nd in node.childNodes:
				if nd.nodeName!="#text" and nd.nodeName!="desc":
					#print(nd.firstChild.data)
					feature=nd.firstChild.data
					if vulname not in vulhub.keys():
						vulhub[vulname]={}
					if 'item' not in vulhub[vulname].keys():
						vulhub[vulname]['item']=[]
					vulhub[vulname]['item'].append(feature)
				elif nd.nodeName=="desc":
					if vulname not in vulhub.keys():
						vulhub[vulname]={}
					if 'item' not in vulhub[vulname].keys():
						vulhub[vulname]['item']=[]
					vulhub[vulname]['desc']=nd.firstChild.data
				else:
					pass
	return vulhub
def FindRefFromSingleClass(path):
	resultfile=open("result.html",'w+')
	resultfile2=open("result.txt",'w+')
	features=getFeatureFromXml()
	for root,dirs,files,in os.walk(path):
			for file in files:
				if os.path.splitext(file)[1] == '.java' or os.path.splitext(file)[1] == '.jsp':
					refs={}
					#print(os.path.join(root,file))
					filepath=os.path.join(root,file)
					className=os.path.splitext(file)[0]
					print("开始扫描类文件："+filepath)
					f=open(filepath,'rb')
					lines=f.readlines()
					lineslen=len(lines)
					className=os.path.splitext(file)[0]
					try:
						while lineslen>0:
								lineslen=lineslen-1
								linecode=lines[lineslen]
								linecode=str(linecode,encoding="utf-8")	
								for vulname in features.keys():
									for feature in features[vulname]['item']:
										if feature in linecode:
											print("[+]找到疑似"+vulname+"漏洞点，地址是："+filepath)
											vulinfo={}
											vulinfo["path"]=filepath
											vulinfo["linecode"]=linecode
											vulinfo["line"]=str(lineslen)
											if vulname not in resultinfo.keys():
												resultinfo[vulname]=[]
											resultinfo[vulname].append(vulinfo)
											resultfile2.write("[+]checked:"+vulname+" 地址："+filepath+"行数："+str(lineslen)+"\n")
										else:
											pass
									
					except:
						pass
	banner_bigin()
	resultfile.write("<h2>白盒扫描漏洞报告</h2>")
	for vul in resultinfo.keys():
		resultfile.write("<div><h3>"+vul+"漏洞</h3>")
		count=0
		for vulitem in resultinfo[vul]:
			count=count+1
			print("[+]找到疑似"+vul+"漏洞点！")
			print("代码是："+vulitem["linecode"].strip())
			print("行数："+vulitem["line"])
			print("路径："+vulitem["path"])
			resultfile.write("<h4>第"+str(count)+"处漏洞点</h4>")
			resultfile.write("<p>代码是："+vulitem["linecode"].strip()+"</p>")
			resultfile.write("<p>行数："+vulitem["line"]+"</p>")
			resultfile.write("<p>路径："+vulitem["path"]+"</p>")
			resultfile.write("</div>")
	banner_finished()
if __name__ == '__main__':
	path="./workspace"
	FindRefFromSingleClass(path)
